'use strict';

const { query, queryOne, execute } = require('../config/db');
const permissionWrite = require('../services/permissionWrite.service');
const audit = require('../services/audit.service');
const { asyncHandler } = require('../middleware/error');
const { clientIp } = require('./helpers');

function slugify(s) {
  return String(s).toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// GET /super-admin/companies?includeDeleted=
const list = asyncHandler(async (req, res) => {
  const includeDeleted = String(req.query.includeDeleted) === 'true';
  const rows = await query(
    `SELECT c.*,
            (SELECT COUNT(*) FROM users u WHERE u.company_id = c.id AND u.deleted_at IS NULL) AS user_count,
            (SELECT COUNT(*) FROM teams t WHERE t.company_id = c.id AND t.deleted_at IS NULL) AS team_count
       FROM companies c
      ${includeDeleted ? '' : 'WHERE c.deleted_at IS NULL'}
      ORDER BY c.name`
  );
  res.json({ companies: rows });
});

// POST /super-admin/companies  { name, selfManagePermissions? }
const create = asyncHandler(async (req, res) => {
  const { name, selfManagePermissions = false } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });
  let slug = slugify(name);
  const dup = await queryOne('SELECT id FROM companies WHERE slug = :s', { s: slug });
  if (dup) slug = `${slug}-${Date.now().toString().slice(-4)}`;
  const result = await execute(
    `INSERT INTO companies (name, slug, status, self_manage_permissions)
     VALUES (:n, :s, 'active', :self)`,
    { n: name, s: slug, self: selfManagePermissions ? 1 : 0 }
  );
  await audit.record({
    actor: req.user, action: 'company.create', entityType: 'company', entityId: result.insertId,
    companyId: result.insertId, changes: { name }, ip: clientIp(req),
  });
  res.status(201).json({ id: result.insertId, slug });
});

// PUT /super-admin/companies/:id  { name?, selfManagePermissions? }
const update = asyncHandler(async (req, res) => {
  const id = req.params.id;
  const { name, selfManagePermissions } = req.body || {};
  const fields = [];
  const params = { id };
  if (name) { fields.push('name = :name'); params.name = name; }
  if (typeof selfManagePermissions === 'boolean') {
    fields.push('self_manage_permissions = :self'); params.self = selfManagePermissions ? 1 : 0;
  }
  if (!fields.length) return res.status(400).json({ error: 'nothing to update' });
  await execute(`UPDATE companies SET ${fields.join(', ')} WHERE id = :id`, params);
  await audit.record({
    actor: req.user, action: 'company.update', entityType: 'company', entityId: Number(id),
    companyId: Number(id), changes: { name, selfManagePermissions }, ip: clientIp(req),
  });
  res.json({ ok: true });
});

// POST /super-admin/companies/:id/activate  { active: bool }
const setActive = asyncHandler(async (req, res) => {
  const id = req.params.id;
  const active = req.body?.active !== false;
  await execute('UPDATE companies SET status = :s WHERE id = :id', { s: active ? 'active' : 'inactive', id });
  await audit.record({
    actor: req.user, action: active ? 'company.activate' : 'company.deactivate',
    entityType: 'company', entityId: Number(id), companyId: Number(id), ip: clientIp(req),
  });
  res.json({ ok: true, status: active ? 'active' : 'inactive' });
});

// DELETE /super-admin/companies/:id — soft delete
const remove = asyncHandler(async (req, res) => {
  const id = req.params.id;
  await execute('UPDATE companies SET deleted_at = NOW() WHERE id = :id', { id });
  await audit.record({
    actor: req.user, action: 'company.delete', entityType: 'company', entityId: Number(id),
    companyId: Number(id), ip: clientIp(req),
  });
  res.json({ ok: true });
});

// POST /super-admin/companies/:id/restore
const restore = asyncHandler(async (req, res) => {
  const id = req.params.id;
  await execute('UPDATE companies SET deleted_at = NULL WHERE id = :id', { id });
  await audit.record({
    actor: req.user, action: 'company.restore', entityType: 'company', entityId: Number(id),
    companyId: Number(id), ip: clientIp(req),
  });
  res.json({ ok: true });
});

// GET /super-admin/companies/:id/permissions — the company boundary matrix
const getBoundary = asyncHandler(async (req, res) => {
  const id = req.params.id;
  const rows = await query(
    `SELECT p.\`key\`, g.\`key\` AS group_key, g.label AS group_label, p.label, p.action,
            (SELECT effect FROM company_permissions cp WHERE cp.company_id = :c AND cp.permission_id = p.id) AS effect
       FROM permissions p JOIN permission_groups g ON g.id = p.group_id
      WHERE p.is_system = 0
      ORDER BY g.sort_order, p.id`,
    { c: id }
  );
  const groups = new Map();
  for (const r of rows) {
    if (!groups.has(r.group_key)) groups.set(r.group_key, { key: r.group_key, label: r.group_label, permissions: [] });
    groups.get(r.group_key).permissions.push({
      key: r.key, label: r.label, action: r.action,
      disabled: r.effect === 'deny', // disabled for the company
    });
  }
  res.json({ groups: Array.from(groups.values()) });
});

// PUT /super-admin/companies/:id/permissions  { disabledKeys: [] }
const setBoundary = asyncHandler(async (req, res) => {
  const id = req.params.id;
  const disabledKeys = Array.isArray(req.body?.disabledKeys) ? req.body.disabledKeys : [];
  await permissionWrite.setCompanyBoundary(req.user, id, disabledKeys, clientIp(req));
  res.json({ ok: true, disabled: disabledKeys.length });
});

// ---- Company self-service boundary (section 9) ----------------------------
// A company admin may configure their OWN company's boundary only if the
// Super Admin enabled self_manage_permissions for that company.
async function assertSelfManage(companyId) {
  const c = await queryOne('SELECT self_manage_permissions FROM companies WHERE id = :id', { id: companyId });
  if (!c) throw Object.assign(new Error('Company not found'), { status: 404 });
  if (!c.self_manage_permissions) {
    throw Object.assign(new Error('Company is not permitted to self-manage permissions'), { status: 403 });
  }
}

// GET /admin/company/permissions
const getOwnBoundary = asyncHandler(async (req, res) => {
  req.params.id = req.user.company_id;
  await assertSelfManage(req.user.company_id);
  return getBoundary(req, res);
});

// PUT /admin/company/permissions
const setOwnBoundary = asyncHandler(async (req, res) => {
  req.params.id = req.user.company_id;
  await assertSelfManage(req.user.company_id);
  return setBoundary(req, res);
});

module.exports = {
  list, create, update, setActive, remove, restore,
  getBoundary, setBoundary, getOwnBoundary, setOwnBoundary,
};
