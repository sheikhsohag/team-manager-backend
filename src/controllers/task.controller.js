'use strict';

const { query, queryOne, execute } = require('../config/db');
const audit = require('../services/audit.service');
const { asyncHandler } = require('../middleware/error');
const { clientIp } = require('./helpers');

// company scoping helper
function companyScope(req) {
  return req.user.is_super_admin && req.query.companyId
    ? Number(req.query.companyId)
    : req.user.company_id;
}

// GET /tasks
const list = asyncHandler(async (req, res) => {
  const params = { c: companyScope(req) };
  const rows = await query(
    `SELECT t.*, u.name AS assignee_name FROM tasks t
       LEFT JOIN users u ON u.id = t.assignee_id
      WHERE t.deleted_at IS NULL ${params.c ? 'AND t.company_id = :c' : ''}
      ORDER BY t.updated_at DESC LIMIT 200`,
    params.c ? params : {}
  );
  res.json({ tasks: rows });
});

// POST /tasks  { title, description?, projectId?, priority? }
const create = asyncHandler(async (req, res) => {
  const { title, description = null, projectId = null, priority = 'medium' } = req.body || {};
  if (!title) return res.status(400).json({ error: 'title is required' });
  const companyId = companyScope(req);
  const result = await execute(
    `INSERT INTO tasks (company_id, project_id, title, description, priority, created_by)
     VALUES (:c, :p, :t, :d, :pri, :cb)`,
    { c: companyId, p: projectId, t: title, d: description, pri: priority, cb: req.user.id }
  );
  await audit.record({
    actor: req.user, action: 'task.create', entityType: 'task', entityId: result.insertId,
    companyId, changes: { title }, ip: clientIp(req),
  });
  res.status(201).json({ id: result.insertId });
});

async function loadTaskScoped(req) {
  const task = await queryOne('SELECT * FROM tasks WHERE id = :id AND deleted_at IS NULL', { id: req.params.id });
  if (!task) throw Object.assign(new Error('Task not found'), { status: 404 });
  if (!req.user.is_super_admin && Number(task.company_id) !== Number(req.user.company_id)) {
    throw Object.assign(new Error('Cross-company access denied'), { status: 403 });
  }
  return task;
}

// POST /tasks/:id/status  { status }
const changeStatus = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  const { status } = req.body || {};
  const allowed = ['todo', 'in_progress', 'done', 'reopened'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'invalid status' });
  await execute('UPDATE tasks SET status = :s WHERE id = :id', { s: status, id: task.id });
  await audit.record({
    actor: req.user, action: 'task.change_status', entityType: 'task', entityId: task.id,
    companyId: task.company_id, changes: { from: task.status, to: status }, ip: clientIp(req),
  });
  res.json({ ok: true });
});

// DELETE /tasks/:id
const remove = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  await execute('UPDATE tasks SET deleted_at = NOW() WHERE id = :id', { id: task.id });
  await audit.record({
    actor: req.user, action: 'task.delete', entityType: 'task', entityId: task.id,
    companyId: task.company_id, ip: clientIp(req),
  });
  res.json({ ok: true });
});

module.exports = { list, create, changeStatus, remove };
