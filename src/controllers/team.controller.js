'use strict';

const { query, queryOne, execute } = require('../config/db');
const audit = require('../services/audit.service');
const { asyncHandler } = require('../middleware/error');
const { clientIp } = require('./helpers');

function scope(req) {
  return req.user.is_super_admin && req.query.companyId ? Number(req.query.companyId) : req.user.company_id;
}

async function loadTeamScoped(req) {
  const team = await queryOne('SELECT * FROM teams WHERE id = :id AND deleted_at IS NULL', { id: req.params.id });
  if (!team) throw Object.assign(new Error('Team not found'), { status: 404 });
  if (!req.user.is_super_admin && Number(team.company_id) !== Number(req.user.company_id)) {
    throw Object.assign(new Error('Cross-company access denied'), { status: 403 });
  }
  return team;
}

// GET /teams
const list = asyncHandler(async (req, res) => {
  const companyId = scope(req);
  const rows = await query(
    `SELECT t.*, (SELECT COUNT(*) FROM team_members m WHERE m.team_id = t.id) AS member_count
       FROM teams t
      WHERE t.deleted_at IS NULL ${companyId ? 'AND t.company_id = :c' : ''}
      ORDER BY t.name`,
    companyId ? { c: companyId } : {}
  );
  res.json({ teams: rows });
});

// POST /teams  { name }
const create = asyncHandler(async (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });
  const companyId = scope(req);
  const r = await execute('INSERT INTO teams (company_id, name) VALUES (:c, :n)', { c: companyId, n: name });
  await audit.record({ actor: req.user, action: 'team.create', entityType: 'team', entityId: r.insertId, companyId, changes: { name }, ip: clientIp(req) });
  res.status(201).json({ id: r.insertId });
});

// DELETE /teams/:id
const remove = asyncHandler(async (req, res) => {
  const team = await loadTeamScoped(req);
  await execute('UPDATE teams SET deleted_at = NOW() WHERE id = :id', { id: team.id });
  await audit.record({ actor: req.user, action: 'team.delete', entityType: 'team', entityId: team.id, companyId: team.company_id, ip: clientIp(req) });
  res.json({ ok: true });
});

// GET /teams/:id/members
const members = asyncHandler(async (req, res) => {
  const team = await loadTeamScoped(req);
  const rows = await query(
    `SELECT u.id, u.name, u.email FROM team_members m JOIN users u ON u.id = m.user_id WHERE m.team_id = :t`,
    { t: team.id }
  );
  res.json({ members: rows });
});

// POST /teams/:id/members  { userId }
const addMember = asyncHandler(async (req, res) => {
  const team = await loadTeamScoped(req);
  const { userId } = req.body || {};
  const u = await queryOne('SELECT id, company_id FROM users WHERE id = :id AND deleted_at IS NULL', { id: userId });
  if (!u) return res.status(404).json({ error: 'User not found' });
  if (Number(u.company_id) !== Number(team.company_id)) return res.status(400).json({ error: 'User is in another company' });
  await execute('INSERT IGNORE INTO team_members (team_id, user_id) VALUES (:t, :u)', { t: team.id, u: userId });
  await audit.record({ actor: req.user, action: 'team.add_member', entityType: 'team', entityId: team.id, targetUserId: userId, companyId: team.company_id, ip: clientIp(req) });
  res.json({ ok: true });
});

// DELETE /teams/:id/members/:userId
const removeMember = asyncHandler(async (req, res) => {
  const team = await loadTeamScoped(req);
  await execute('DELETE FROM team_members WHERE team_id = :t AND user_id = :u', { t: team.id, u: req.params.userId });
  await audit.record({ actor: req.user, action: 'team.remove_member', entityType: 'team', entityId: team.id, targetUserId: Number(req.params.userId), companyId: team.company_id, ip: clientIp(req) });
  res.json({ ok: true });
});

module.exports = { list, create, remove, members, addMember, removeMember };
