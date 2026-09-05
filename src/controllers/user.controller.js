'use strict';

const { query, queryOne, execute } = require('../config/db');
const authService = require('../services/auth.service');
const permissionService = require('../services/permission.service');
const permissionWrite = require('../services/permissionWrite.service');
const audit = require('../services/audit.service');
const { asyncHandler } = require('../middleware/error');
const { clientIp, getUserOr404, assertCanManageUser } = require('./helpers');

// GET /users?companyId= — list users (scoped to company for non-super-admins)
const list = asyncHandler(async (req, res) => {
  const params = {};
  const where = ['u.deleted_at IS NULL'];
  if (req.user.is_super_admin) {
    if (req.query.companyId) { where.push('u.company_id = :companyId'); params.companyId = req.query.companyId; }
  } else {
    where.push('u.company_id = :companyId'); params.companyId = req.user.company_id;
  }
  const rows = await query(
    `SELECT u.id, u.name, u.email, u.status, u.company_id, u.is_super_admin, u.last_login_at,
            c.name AS company_name,
            GROUP_CONCAT(DISTINCT r.name ORDER BY r.name SEPARATOR ', ') AS roles
       FROM users u
       LEFT JOIN companies c ON c.id = u.company_id
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
      WHERE ${where.join(' AND ')}
      GROUP BY u.id
      ORDER BY u.name`,
    params
  );
  res.json({ users: rows });
});

// GET /users/:id
const getOne = asyncHandler(async (req, res) => {
  const user = await getUserOr404(req.params.id);
  assertCanManageUser(req.user, user);
  const roles = await query(
    `SELECT r.id, r.name, r.slug FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = :u`,
    { u: user.id }
  );
  res.json({ user: { ...user, deleted_at: undefined }, roles });
});

// POST /users  { name, email, password, companyId?, roleIds? }
const create = asyncHandler(async (req, res) => {
  const { name, email, password, roleIds = [] } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'name, email, password are required' });

  const companyId = req.user.is_super_admin ? (req.body.companyId || null) : req.user.company_id;
  if (!req.user.is_super_admin && !companyId) return res.status(400).json({ error: 'companyId required' });

  const exists = await queryOne('SELECT id FROM users WHERE email = :e', { e: String(email).toLowerCase() });
  if (exists) return res.status(409).json({ error: 'Email already in use' });

  const hash = await authService.hashPassword(password);
  const result = await execute(
    `INSERT INTO users (company_id, name, email, password_hash, status)
     VALUES (:c, :n, :e, :h, 'active')`,
    { c: companyId, n: name, e: String(email).toLowerCase(), h: hash }
  );
  const userId = result.insertId;
  for (const rid of roleIds) {
    await execute('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (:u, :r)', { u: userId, r: rid });
  }
  await audit.record({
    actor: req.user, action: 'user.create', entityType: 'user', entityId: userId,
    targetUserId: userId, companyId, changes: { name, email, roleIds }, ip: clientIp(req),
  });
  res.status(201).json({ id: userId });
});

// PUT /users/:id  { name?, email?, status?, roleIds? }
const update = asyncHandler(async (req, res) => {
  const user = await getUserOr404(req.params.id);
  assertCanManageUser(req.user, user);
  const { name, email, roleIds } = req.body || {};

  const fields = [];
  const params = { id: user.id };
  if (name) { fields.push('name = :name'); params.name = name; }
  if (email) { fields.push('email = :email'); params.email = String(email).toLowerCase(); }
  if (fields.length) await execute(`UPDATE users SET ${fields.join(', ')} WHERE id = :id`, params);

  if (Array.isArray(roleIds)) {
    await execute('DELETE FROM user_roles WHERE user_id = :u', { u: user.id });
    for (const rid of roleIds) {
      await execute('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (:u, :r)', { u: user.id, r: rid });
    }
    permissionService.invalidateUser(user.id);
  }
  await audit.record({
    actor: req.user, action: 'user.update', entityType: 'user', entityId: user.id,
    targetUserId: user.id, changes: { name, email, roleIds }, ip: clientIp(req),
  });
  res.json({ ok: true });
});

async function setStatus(req, res, status, action) {
  const user = await getUserOr404(req.params.id);
  assertCanManageUser(req.user, user);
  await execute('UPDATE users SET status = :s WHERE id = :id', { s: status, id: user.id });
  await audit.record({
    actor: req.user, action, entityType: 'user', entityId: user.id, targetUserId: user.id, ip: clientIp(req),
  });
  res.json({ ok: true, status });
}
const suspend = asyncHandler((req, res) => setStatus(req, res, 'suspended', 'user.suspend'));
const activate = asyncHandler((req, res) => setStatus(req, res, 'active', 'user.restore'));

// DELETE /users/:id — soft delete
const remove = asyncHandler(async (req, res) => {
  const user = await getUserOr404(req.params.id);
  assertCanManageUser(req.user, user);
  await execute('UPDATE users SET deleted_at = NOW() WHERE id = :id', { id: user.id });
  permissionService.invalidateUser(user.id);
  await audit.record({
    actor: req.user, action: 'user.delete', entityType: 'user', entityId: user.id,
    targetUserId: user.id, ip: clientIp(req),
  });
  res.json({ ok: true });
});

// POST /users/:id/reset-password  { newPassword }
const resetPassword = asyncHandler(async (req, res) => {
  const user = await getUserOr404(req.params.id);
  assertCanManageUser(req.user, user);
  const { newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'newPassword min 8 chars' });
  const hash = await authService.hashPassword(newPassword);
  await execute('UPDATE users SET password_hash = :h WHERE id = :id', { h: hash, id: user.id });
  await audit.record({
    actor: req.user, action: 'user.reset_password', entityType: 'user', entityId: user.id,
    targetUserId: user.id, ip: clientIp(req),
  });
  res.json({ ok: true });
});

// GET /users/:id/effective-permissions — the full matrix + sources + summary
const effectivePermissions = asyncHandler(async (req, res) => {
  const user = await getUserOr404(req.params.id);
  assertCanManageUser(req.user, user);
  const eff = await permissionService.effectiveForUi(user.id);
  res.json(eff);
});

// PUT /users/:id/permissions  { changes: [{ key, effect: allow|deny|inherit }] }
const setPermissions = asyncHandler(async (req, res) => {
  const user = await getUserOr404(req.params.id);
  assertCanManageUser(req.user, user);
  const changes = Array.isArray(req.body?.changes) ? req.body.changes : [];
  if (!changes.length) return res.status(400).json({ error: 'changes[] is required' });

  // Boundary enforcement: a non-super actor cannot ALLOW something disabled for
  // the company (prevents privilege escalation).
  if (!req.user.is_super_admin && user.company_id) {
    const disabled = await query(
      `SELECT p.\`key\` FROM company_permissions cp JOIN permissions p ON p.id = cp.permission_id
        WHERE cp.company_id = :c AND cp.effect = 'deny'`, { c: user.company_id }
    );
    const disabledSet = new Set(disabled.map((r) => r.key));
    const violation = changes.find((ch) => ch.effect === 'allow' && disabledSet.has(ch.key));
    if (violation) {
      return res.status(403).json({
        error: 'Company boundary violation',
        message: `Cannot grant "${violation.key}" — it is disabled by company policy.`,
      });
    }
  }

  const result = await permissionWrite.setUserOverrides(req.user, user.id, changes, clientIp(req));
  const eff = await permissionService.effectiveForUi(user.id);
  res.json({ ...result, summary: eff.summary });
});

// POST /users/:id/permissions/reset — reset overrides to role defaults
const resetToRole = asyncHandler(async (req, res) => {
  const user = await getUserOr404(req.params.id);
  assertCanManageUser(req.user, user);
  const result = await permissionWrite.resetUserToRole(req.user, user.id, clientIp(req));
  res.json(result);
});

// POST /users/:id/permissions/apply-template  { templateId, mode }
const applyTemplate = asyncHandler(async (req, res) => {
  const user = await getUserOr404(req.params.id);
  assertCanManageUser(req.user, user);
  const { templateId, mode = 'merge' } = req.body || {};
  if (!templateId) return res.status(400).json({ error: 'templateId is required' });
  const result = await permissionWrite.applyTemplateToUser(req.user, user.id, templateId, mode, clientIp(req));
  res.json(result);
});

module.exports = {
  list, getOne, create, update, suspend, activate, remove, resetPassword,
  effectivePermissions, setPermissions, resetToRole, applyTemplate,
};
