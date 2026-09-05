'use strict';

const { query, queryOne, execute } = require('../config/db');
const permissionWrite = require('../services/permissionWrite.service');
const permissionService = require('../services/permission.service');
const audit = require('../services/audit.service');
const { asyncHandler } = require('../middleware/error');
const { clientIp } = require('./helpers');

function slugify(s) {
  return String(s).toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// GET /roles — system roles + (for the actor's company) custom roles
const list = asyncHandler(async (req, res) => {
  const params = {};
  let scope = 'r.company_id IS NULL';
  if (req.user.is_super_admin) {
    if (req.query.companyId) { scope = '(r.company_id IS NULL OR r.company_id = :c)'; params.c = req.query.companyId; }
  } else {
    scope = '(r.company_id IS NULL OR r.company_id = :c)'; params.c = req.user.company_id;
  }
  const rows = await query(
    `SELECT r.id, r.name, r.slug, r.level, r.is_system, r.company_id, r.description,
            (SELECT COUNT(*) FROM role_permissions rp WHERE rp.role_id = r.id) AS permission_count,
            (SELECT COUNT(*) FROM user_roles ur WHERE ur.role_id = r.id) AS user_count
       FROM roles r
      WHERE ${scope}
      ORDER BY r.is_system DESC, r.level, r.name`,
    params
  );
  res.json({ roles: rows });
});

// GET /roles/:id — role + its permission keys
const getOne = asyncHandler(async (req, res) => {
  const role = await queryOne('SELECT * FROM roles WHERE id = :id', { id: req.params.id });
  if (!role) return res.status(404).json({ error: 'Role not found' });
  if (!req.user.is_super_admin && role.company_id && Number(role.company_id) !== Number(req.user.company_id)) {
    return res.status(403).json({ error: 'Cross-company access denied' });
  }
  const perms = await query(
    `SELECT p.\`key\` FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
      WHERE rp.role_id = :id`, { id: role.id }
  );
  res.json({ role, permissions: perms.map((p) => p.key) });
});

// POST /roles  { name, level?, description?, permissions?[], companyId? }
const create = asyncHandler(async (req, res) => {
  const { name, level = 'company', description = null, permissions = [] } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });

  // Super admin can create system (company_id NULL) or company roles;
  // company admin can only create roles inside their own company.
  const companyId = req.user.is_super_admin ? (req.body.companyId || null) : req.user.company_id;

  const slug = slugify(name);
  const result = await execute(
    `INSERT INTO roles (company_id, name, slug, level, is_system, description)
     VALUES (:c, :n, :s, :lvl, 0, :d)`,
    { c: companyId, n: name, s: slug, lvl: level, d: description }
  );
  const roleId = result.insertId;
  if (permissions.length) {
    await permissionWrite.setRolePermissions(req.user, roleId, permissions, clientIp(req));
  }
  await audit.record({
    actor: req.user, action: 'role.create', entityType: 'role', entityId: roleId,
    companyId, changes: { name, level, permissions }, ip: clientIp(req),
  });
  res.status(201).json({ id: roleId, slug });
});

// PUT /roles/:id  { name?, description? }
const update = asyncHandler(async (req, res) => {
  const role = await queryOne('SELECT * FROM roles WHERE id = :id', { id: req.params.id });
  if (!role) return res.status(404).json({ error: 'Role not found' });
  if (!req.user.is_super_admin && Number(role.company_id) !== Number(req.user.company_id)) {
    return res.status(403).json({ error: 'Cross-company access denied' });
  }
  const { name, description } = req.body || {};
  const fields = [];
  const params = { id: role.id };
  if (name) { fields.push('name = :name'); params.name = name; }
  if (description !== undefined) { fields.push('description = :description'); params.description = description; }
  if (fields.length) await execute(`UPDATE roles SET ${fields.join(', ')} WHERE id = :id`, params);
  res.json({ ok: true });
});

// PUT /roles/:id/permissions  { permissions: [] }
const setPermissions = asyncHandler(async (req, res) => {
  const role = await queryOne('SELECT * FROM roles WHERE id = :id', { id: req.params.id });
  if (!role) return res.status(404).json({ error: 'Role not found' });
  if (!req.user.is_super_admin && Number(role.company_id) !== Number(req.user.company_id)) {
    return res.status(403).json({ error: 'Cross-company access denied' });
  }
  const permissions = Array.isArray(req.body?.permissions) ? req.body.permissions : [];
  await permissionWrite.setRolePermissions(req.user, role.id, permissions, clientIp(req));
  res.json({ ok: true, count: permissions.length });
});

// DELETE /roles/:id — only custom (non-system) roles
const remove = asyncHandler(async (req, res) => {
  const role = await queryOne('SELECT * FROM roles WHERE id = :id', { id: req.params.id });
  if (!role) return res.status(404).json({ error: 'Role not found' });
  if (role.is_system) return res.status(400).json({ error: 'System roles cannot be deleted' });
  if (!req.user.is_super_admin && Number(role.company_id) !== Number(req.user.company_id)) {
    return res.status(403).json({ error: 'Cross-company access denied' });
  }
  // invalidate everyone holding it, then delete (cascades role_permissions/user_roles)
  await permissionService.invalidateRole(role.id);
  await execute('DELETE FROM roles WHERE id = :id', { id: role.id });
  await audit.record({
    actor: req.user, action: 'role.delete', entityType: 'role', entityId: role.id,
    companyId: role.company_id, changes: { name: role.name }, ip: clientIp(req),
  });
  res.json({ ok: true });
});

module.exports = { list, getOne, create, update, setPermissions, remove };
