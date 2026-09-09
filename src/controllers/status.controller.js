'use strict';

const { query, queryOne, execute } = require('../config/db');
const audit = require('../services/audit.service');
const { asyncHandler } = require('../middleware/error');
const { clientIp } = require('./helpers');

function companyScope(req) {
  return req.user.is_super_admin && req.query.companyId
    ? Number(req.query.companyId)
    : req.user.company_id;
}

// GET /statuses  — any authenticated user may read (to render pickers/filters)
const list = asyncHandler(async (req, res) => {
  const companyId = companyScope(req);
  if (!companyId) return res.json({ statuses: [] });
  const rows = await query(
    `SELECT id, name, note, color, sort_order, is_default, is_done
       FROM task_statuses WHERE company_id = :c
      ORDER BY sort_order ASC, id ASC`,
    { c: companyId }
  );
  res.json({ statuses: rows });
});

// POST /statuses  { name, note?, color?, sortOrder?, isDefault?, isDone? }
const create = asyncHandler(async (req, res) => {
  const companyId = companyScope(req);
  if (!companyId) return res.status(400).json({ error: 'No company context' });
  const { name, note = null, color = 'grey', sortOrder = 100, isDefault = false, isDone = false } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'name is required' });

  const dup = await queryOne('SELECT id FROM task_statuses WHERE company_id = :c AND name = :n', { c: companyId, n: String(name).trim() });
  if (dup) return res.status(409).json({ error: 'A status with this name already exists' });

  if (isDefault) {
    await execute('UPDATE task_statuses SET is_default = 0 WHERE company_id = :c', { c: companyId });
  }
  const r = await execute(
    `INSERT INTO task_statuses (company_id, name, note, color, sort_order, is_default, is_done, created_by)
     VALUES (:c, :n, :note, :color, :sort, :def, :done, :by)`,
    { c: companyId, n: String(name).trim(), note, color, sort: Number(sortOrder) || 0, def: isDefault ? 1 : 0, done: isDone ? 1 : 0, by: req.user.id }
  );
  await audit.record({
    actor: req.user, action: 'task.status_create', entityType: 'task_status', entityId: r.insertId,
    companyId, changes: { name }, ip: clientIp(req),
  });
  res.status(201).json({ id: r.insertId });
});

// PUT /statuses/:id
const update = asyncHandler(async (req, res) => {
  const companyId = companyScope(req);
  const status = await queryOne('SELECT * FROM task_statuses WHERE id = :id', { id: req.params.id });
  if (!status) return res.status(404).json({ error: 'Status not found' });
  if (!req.user.is_super_admin && Number(status.company_id) !== Number(req.user.company_id)) {
    return res.status(403).json({ error: 'Cross-company access denied' });
  }
  const body = req.body || {};
  const fields = [];
  const params = { id: status.id };
  const map = { name: 'name', note: 'note', color: 'color', sortOrder: 'sort_order' };
  for (const [key, col] of Object.entries(map)) {
    if (key in body) { fields.push(`${col} = :${key}`); params[key] = body[key]; }
  }
  if ('isDone' in body) { fields.push('is_done = :isDone'); params.isDone = body.isDone ? 1 : 0; }
  if (body.isDefault) {
    await execute('UPDATE task_statuses SET is_default = 0 WHERE company_id = :c', { c: status.company_id });
    fields.push('is_default = 1');
  }
  if (!fields.length) return res.status(400).json({ error: 'No fields to update' });
  await execute(`UPDATE task_statuses SET ${fields.join(', ')} WHERE id = :id`, params);
  await audit.record({
    actor: req.user, action: 'task.status_update', entityType: 'task_status', entityId: status.id,
    companyId: status.company_id, changes: body, ip: clientIp(req),
  });
  res.json({ ok: true });
});

// DELETE /statuses/:id  (tasks referencing it fall back to NULL via FK)
const remove = asyncHandler(async (req, res) => {
  const status = await queryOne('SELECT * FROM task_statuses WHERE id = :id', { id: req.params.id });
  if (!status) return res.status(404).json({ error: 'Status not found' });
  if (!req.user.is_super_admin && Number(status.company_id) !== Number(req.user.company_id)) {
    return res.status(403).json({ error: 'Cross-company access denied' });
  }
  const count = await queryOne('SELECT COUNT(*) AS n FROM task_statuses WHERE company_id = :c', { c: status.company_id });
  if (Number(count.n) <= 1) return res.status(400).json({ error: 'Cannot delete the last remaining status' });
  await execute('DELETE FROM task_statuses WHERE id = :id', { id: status.id });
  await audit.record({
    actor: req.user, action: 'task.status_delete', entityType: 'task_status', entityId: status.id,
    companyId: status.company_id, changes: { name: status.name }, ip: clientIp(req),
  });
  res.json({ ok: true });
});

module.exports = { list, create, update, remove };
