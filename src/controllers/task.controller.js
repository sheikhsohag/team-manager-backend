'use strict';

const fs = require('fs');
const path = require('path');
const { query, queryOne, execute } = require('../config/db');
const audit = require('../services/audit.service');
const permissionService = require('../services/permission.service');
const { visibilityClause, canSee } = require('../services/taskVisibility.service');
const { asyncHandler } = require('../middleware/error');
const { clientIp } = require('./helpers');
const { UPLOAD_DIR } = require('../middleware/upload');

// Which company are we acting in? Super admins may target one via ?companyId=.
function companyScope(req) {
  return req.user.is_super_admin && req.query.companyId
    ? Number(req.query.companyId)
    : req.user.company_id;
}

function hasViewAll(req) {
  return permissionService.can(req.user.id, 'task.view_all');
}

// Task row + joined display fields.
const SELECT_TASK = `
  SELECT t.*,
         a.name  AS assignee_name,
         c.name  AS creator_name,
         tm.name AS team_name,
         s.name  AS status_name, s.color AS status_color, s.is_done AS status_is_done,
         (SELECT COUNT(*) FROM tasks st WHERE st.parent_id = t.id AND st.deleted_at IS NULL) AS subtask_count,
         (SELECT COUNT(*) FROM task_comments tc WHERE tc.task_id = t.id) AS comment_count,
         (SELECT COUNT(*) FROM task_attachments ta WHERE ta.task_id = t.id) AS attachment_count
    FROM tasks t
    LEFT JOIN users a  ON a.id = t.assignee_id
    LEFT JOIN users c  ON c.id = t.created_by
    LEFT JOIN teams tm ON tm.id = t.team_id
    LEFT JOIN task_statuses s ON s.id = t.status_id`;

async function loadTaskScoped(req) {
  const task = await queryOne('SELECT * FROM tasks WHERE id = :id AND deleted_at IS NULL', { id: req.params.id });
  if (!task) throw Object.assign(new Error('Task not found'), { status: 404 });
  if (!req.user.is_super_admin && Number(task.company_id) !== Number(req.user.company_id)) {
    throw Object.assign(new Error('Cross-company access denied'), { status: 403 });
  }
  return task;
}

async function assertCanSee(req, task) {
  const viewAll = await hasViewAll(req);
  const ok = await canSee(req.user, task, viewAll);
  if (!ok) throw Object.assign(new Error('You do not have access to this task'), { status: 403 });
}

// GET /tasks  — filters: scope=all|mine, assigneeId, statusId, teamId, parentId,
//               from, to (created_at date range), q, top=1 (only top-level)
const list = asyncHandler(async (req, res) => {
  const companyId = companyScope(req);
  const { scope = 'mine', assigneeId, statusId, teamId, parentId, from, to, q, top } = req.query;

  const where = ['t.deleted_at IS NULL'];
  const params = { me: req.user.id };

  if (companyId) { where.push('t.company_id = :c'); params.c = companyId; }

  // Visibility: view_all + scope=all lets admins see everything in company.
  const viewAll = await hasViewAll(req);
  if (!(viewAll && scope === 'all') && !req.user.is_super_admin) {
    where.push(visibilityClause());
  }

  if (assigneeId) { where.push('t.assignee_id = :aid'); params.aid = Number(assigneeId); }
  if (statusId) { where.push('t.status_id = :sid'); params.sid = Number(statusId); }
  if (teamId) { where.push('t.team_id = :tid'); params.tid = Number(teamId); }
  if (parentId) { where.push('t.parent_id = :pid'); params.pid = Number(parentId); }
  else if (top === '1' || top === 'true') { where.push('t.parent_id IS NULL'); }
  if (from) { where.push('DATE(t.created_at) >= :from'); params.from = from; }
  if (to) { where.push('DATE(t.created_at) <= :to'); params.to = to; }
  if (q) { where.push('(t.title LIKE :q OR t.heading LIKE :q)'); params.q = `%${q}%`; }

  const rows = await query(
    `${SELECT_TASK} WHERE ${where.join(' AND ')} ORDER BY t.updated_at DESC LIMIT 500`,
    params
  );
  res.json({ tasks: rows });
});

// GET /tasks/:id  — full detail incl. subtasks, comments, attachments, shares
const getOne = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  await assertCanSee(req, task);

  const [full] = await query(`${SELECT_TASK} WHERE t.id = :id`, { id: task.id });
  const subtasks = await query(
    `${SELECT_TASK} WHERE t.parent_id = :id AND t.deleted_at IS NULL ORDER BY t.created_at`,
    { id: task.id }
  );
  const comments = await query(
    `SELECT tc.id, tc.body, tc.created_at, tc.user_id, u.name AS user_name
       FROM task_comments tc LEFT JOIN users u ON u.id = tc.user_id
      WHERE tc.task_id = :id ORDER BY tc.created_at`,
    { id: task.id }
  );
  const attachments = await query(
    `SELECT ta.id, ta.original_name, ta.mime_type, ta.size_bytes, ta.created_at,
            ta.uploaded_by, u.name AS uploaded_by_name
       FROM task_attachments ta LEFT JOIN users u ON u.id = ta.uploaded_by
      WHERE ta.task_id = :id ORDER BY ta.created_at`,
    { id: task.id }
  );
  const shares = await query(
    `SELECT ts.user_id, u.name, u.email FROM task_shares ts
       JOIN users u ON u.id = ts.user_id WHERE ts.task_id = :id`,
    { id: task.id }
  );
  res.json({ task: full, subtasks, comments, attachments, shares });
});

// Resolve the status for a new task: explicit -> validated; else company default.
async function resolveStatusId(companyId, statusId) {
  if (statusId) {
    const s = await queryOne('SELECT id FROM task_statuses WHERE id = :s AND company_id = :c', { s: statusId, c: companyId });
    if (!s) throw Object.assign(new Error('Invalid status for this company'), { status: 400 });
    return s.id;
  }
  const def = await queryOne(
    `SELECT id FROM task_statuses WHERE company_id = :c
      ORDER BY is_default DESC, sort_order ASC, id ASC LIMIT 1`,
    { c: companyId }
  );
  return def ? def.id : null;
}

// POST /tasks
const create = asyncHandler(async (req, res) => {
  const {
    title, heading = null, description = null, projectId = null, teamId = null,
    parentId = null, statusId = null, assigneeId = null, priority = 'medium', dueDate = null,
  } = req.body || {};
  if (!title || !String(title).trim()) return res.status(400).json({ error: 'title is required' });

  let companyId = companyScope(req);
  let resolvedTeamId = teamId;
  let resolvedParentId = null;

  if (parentId) {
    const parent = await queryOne('SELECT * FROM tasks WHERE id = :id AND deleted_at IS NULL', { id: parentId });
    if (!parent) return res.status(404).json({ error: 'Parent task not found' });
    if (!req.user.is_super_admin && Number(parent.company_id) !== Number(req.user.company_id)) {
      return res.status(403).json({ error: 'Cross-company access denied' });
    }
    if (parent.parent_id) return res.status(400).json({ error: 'Subtasks cannot have their own subtasks' });
    companyId = parent.company_id;
    resolvedTeamId = parent.team_id;
    resolvedParentId = parent.id;
  }

  if (assigneeId) {
    const u = await queryOne('SELECT id FROM users WHERE id = :id AND company_id = :c AND deleted_at IS NULL', { id: assigneeId, c: companyId });
    if (!u) return res.status(400).json({ error: 'Assignee is not in this company' });
  }
  if (resolvedTeamId) {
    const tm = await queryOne('SELECT id FROM teams WHERE id = :id AND company_id = :c AND deleted_at IS NULL', { id: resolvedTeamId, c: companyId });
    if (!tm) return res.status(400).json({ error: 'Team is not in this company' });
  }

  const finalStatusId = await resolveStatusId(companyId, statusId);

  const result = await execute(
    `INSERT INTO tasks (company_id, team_id, project_id, parent_id, title, heading, description,
                        status_id, priority, assignee_id, created_by, due_date)
     VALUES (:c, :team, :proj, :parent, :t, :h, :d, :st, :pri, :a, :cb, :due)`,
    {
      c: companyId, team: resolvedTeamId, proj: projectId, parent: resolvedParentId,
      t: String(title).trim(), h: heading, d: description, st: finalStatusId,
      pri: priority, a: assigneeId, cb: req.user.id, due: dueDate || null,
    }
  );
  await audit.record({
    actor: req.user, action: 'task.create', entityType: 'task', entityId: result.insertId,
    companyId, changes: { title, parentId: resolvedParentId }, ip: clientIp(req),
  });
  res.status(201).json({ id: result.insertId });
});

// PUT /tasks/:id
const update = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  const fields = [];
  const params = { id: task.id };
  const body = req.body || {};

  const map = {
    title: 'title', heading: 'heading', description: 'description',
    priority: 'priority', dueDate: 'due_date',
  };
  for (const [key, col] of Object.entries(map)) {
    if (key in body) { fields.push(`${col} = :${key}`); params[key] = body[key] === '' ? null : body[key]; }
  }
  if ('assigneeId' in body) {
    if (body.assigneeId) {
      const u = await queryOne('SELECT id FROM users WHERE id = :id AND company_id = :c AND deleted_at IS NULL', { id: body.assigneeId, c: task.company_id });
      if (!u) return res.status(400).json({ error: 'Assignee is not in this company' });
    }
    fields.push('assignee_id = :assigneeId'); params.assigneeId = body.assigneeId || null;
  }
  if ('teamId' in body) {
    if (body.teamId) {
      const tm = await queryOne('SELECT id FROM teams WHERE id = :id AND company_id = :c AND deleted_at IS NULL', { id: body.teamId, c: task.company_id });
      if (!tm) return res.status(400).json({ error: 'Team is not in this company' });
    }
    fields.push('team_id = :teamId'); params.teamId = body.teamId || null;
  }
  if ('statusId' in body) {
    const sid = await resolveStatusId(task.company_id, body.statusId);
    fields.push('status_id = :statusId'); params.statusId = sid;
  }
  if (!fields.length) return res.status(400).json({ error: 'No fields to update' });

  await execute(`UPDATE tasks SET ${fields.join(', ')} WHERE id = :id`, params);
  await audit.record({
    actor: req.user, action: 'task.update', entityType: 'task', entityId: task.id,
    companyId: task.company_id, changes: body, ip: clientIp(req),
  });
  res.json({ ok: true });
});

// POST /tasks/:id/status  { statusId }
const changeStatus = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  const { statusId } = req.body || {};
  const status = await queryOne(
    'SELECT id, name FROM task_statuses WHERE id = :s AND company_id = :c',
    { s: statusId, c: task.company_id }
  );
  if (!status) return res.status(400).json({ error: 'Invalid status' });
  await execute('UPDATE tasks SET status_id = :s WHERE id = :id', { s: status.id, id: task.id });
  await audit.record({
    actor: req.user, action: 'task.change_status', entityType: 'task', entityId: task.id,
    companyId: task.company_id, changes: { from: task.status_id, to: status.id }, ip: clientIp(req),
  });
  res.json({ ok: true });
});

// DELETE /tasks/:id  (soft delete; subtasks cascade via FK on hard delete only,
// so we soft-delete children too)
const remove = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  await execute('UPDATE tasks SET deleted_at = NOW() WHERE id = :id OR parent_id = :id', { id: task.id });
  await audit.record({
    actor: req.user, action: 'task.delete', entityType: 'task', entityId: task.id,
    companyId: task.company_id, ip: clientIp(req),
  });
  res.json({ ok: true });
});

// ---- Comments -------------------------------------------------------------
const listComments = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  await assertCanSee(req, task);
  const rows = await query(
    `SELECT tc.id, tc.body, tc.created_at, tc.user_id, u.name AS user_name
       FROM task_comments tc LEFT JOIN users u ON u.id = tc.user_id
      WHERE tc.task_id = :id ORDER BY tc.created_at`,
    { id: task.id }
  );
  res.json({ comments: rows });
});

const addComment = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  await assertCanSee(req, task);
  const { body } = req.body || {};
  if (!body || !String(body).trim()) return res.status(400).json({ error: 'body is required' });
  const r = await execute(
    'INSERT INTO task_comments (task_id, user_id, body) VALUES (:t, :u, :b)',
    { t: task.id, u: req.user.id, b: String(body).trim() }
  );
  await audit.record({
    actor: req.user, action: 'task.comment', entityType: 'task', entityId: task.id,
    companyId: task.company_id, ip: clientIp(req),
  });
  res.status(201).json({ id: r.insertId });
});

// ---- Attachments ----------------------------------------------------------
const listAttachments = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  await assertCanSee(req, task);
  const rows = await query(
    `SELECT ta.id, ta.original_name, ta.mime_type, ta.size_bytes, ta.created_at,
            ta.uploaded_by, u.name AS uploaded_by_name
       FROM task_attachments ta LEFT JOIN users u ON u.id = ta.uploaded_by
      WHERE ta.task_id = :id ORDER BY ta.created_at`,
    { id: task.id }
  );
  res.json({ attachments: rows });
});

const uploadAttachment = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  await assertCanSee(req, task);
  if (!req.file) return res.status(400).json({ error: 'No file uploaded (field name: file)' });
  const r = await execute(
    `INSERT INTO task_attachments (task_id, uploaded_by, original_name, stored_name, mime_type, size_bytes)
     VALUES (:t, :u, :orig, :stored, :mime, :size)`,
    {
      t: task.id, u: req.user.id, orig: req.file.originalname,
      stored: req.file.filename, mime: req.file.mimetype, size: req.file.size,
    }
  );
  await audit.record({
    actor: req.user, action: 'task.attach_file', entityType: 'task', entityId: task.id,
    companyId: task.company_id, changes: { file: req.file.originalname }, ip: clientIp(req),
  });
  res.status(201).json({ id: r.insertId, original_name: req.file.originalname });
});

const downloadAttachment = asyncHandler(async (req, res) => {
  const att = await queryOne('SELECT * FROM task_attachments WHERE id = :id', { id: req.params.attId });
  if (!att) return res.status(404).json({ error: 'Attachment not found' });
  const task = await queryOne('SELECT * FROM tasks WHERE id = :id', { id: att.task_id });
  if (!task) return res.status(404).json({ error: 'Task not found' });
  if (!req.user.is_super_admin && Number(task.company_id) !== Number(req.user.company_id)) {
    return res.status(403).json({ error: 'Cross-company access denied' });
  }
  await assertCanSee(req, task);
  const filePath = path.join(UPLOAD_DIR, att.stored_name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File missing on disk' });
  res.download(filePath, att.original_name);
});

const removeAttachment = asyncHandler(async (req, res) => {
  const att = await queryOne('SELECT * FROM task_attachments WHERE id = :id', { id: req.params.attId });
  if (!att) return res.status(404).json({ error: 'Attachment not found' });
  const task = await queryOne('SELECT * FROM tasks WHERE id = :id', { id: att.task_id });
  if (task && !req.user.is_super_admin && Number(task.company_id) !== Number(req.user.company_id)) {
    return res.status(403).json({ error: 'Cross-company access denied' });
  }
  await execute('DELETE FROM task_attachments WHERE id = :id', { id: att.id });
  const filePath = path.join(UPLOAD_DIR, att.stored_name);
  fs.promises.unlink(filePath).catch(() => {});
  res.json({ ok: true });
});

// ---- Per-task sharing -----------------------------------------------------
const shareTask = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  const { userId } = req.body || {};
  const u = await queryOne('SELECT id, company_id FROM users WHERE id = :id AND deleted_at IS NULL', { id: userId });
  if (!u) return res.status(404).json({ error: 'User not found' });
  if (Number(u.company_id) !== Number(task.company_id)) return res.status(400).json({ error: 'User is in another company' });
  await execute(
    'INSERT IGNORE INTO task_shares (task_id, user_id, granted_by) VALUES (:t, :u, :g)',
    { t: task.id, u: userId, g: req.user.id }
  );
  await audit.record({
    actor: req.user, action: 'task.share', entityType: 'task', entityId: task.id,
    targetUserId: userId, companyId: task.company_id, ip: clientIp(req),
  });
  res.json({ ok: true });
});

const unshareTask = asyncHandler(async (req, res) => {
  const task = await loadTaskScoped(req);
  await execute('DELETE FROM task_shares WHERE task_id = :t AND user_id = :u', { t: task.id, u: req.params.userId });
  res.json({ ok: true });
});

module.exports = {
  list, getOne, create, update, changeStatus, remove,
  listComments, addComment,
  listAttachments, uploadAttachment, downloadAttachment, removeAttachment,
  shareTask, unshareTask,
};
