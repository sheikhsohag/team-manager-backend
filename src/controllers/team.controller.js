'use strict';

const { query, queryOne, execute } = require('../config/db');
const audit = require('../services/audit.service');
const permissionService = require('../services/permission.service');
const { asyncHandler } = require('../middleware/error');
const { clientIp } = require('./helpers');
const { TEAM_ROLE_SLUG } = require('../db/seed/catalog');

// Perms a lead/assistant may grant to their own members (nothing escalating).
const GRANTABLE_MEMBER_PERMS = [
  'task.create', 'task.update', 'task.change_status', 'task.complete',
  'task.comment', 'task.add_note', 'task.attach_file', 'task.share', 'task.assign',
];

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

/** Actor may manage this team if super admin, a company-level team admin
 *  (holds team.create), or a lead/assistant_lead of this specific team. */
async function assertCanManageTeam(req, team) {
  if (req.user.is_super_admin) return;
  const companyAdmin = await permissionService.can(req.user.id, 'team.create');
  if (companyAdmin) return;
  const membership = await queryOne(
    "SELECT role_in_team FROM team_members WHERE team_id = :t AND user_id = :u AND role_in_team IN ('lead','assistant_lead')",
    { t: team.id, u: req.user.id }
  );
  if (!membership) throw Object.assign(new Error('You do not manage this team'), { status: 403 });
}

/**
 * Re-derive a user's team-level RBAC role from ALL their memberships and sync
 * user_roles accordingly. Highest membership role wins (lead > assistant > member).
 * Only the three team-level role slugs are touched — company/admin roles are
 * left intact. This is what gives a new lead their auto task-create capability.
 */
async function syncTeamRbacRole(userId) {
  const memberships = await query('SELECT role_in_team FROM team_members WHERE user_id = :u', { u: userId });
  let best = null; // 'lead' | 'assistant_lead' | 'member' | null
  const rank = { lead: 3, assistant_lead: 2, member: 1 };
  for (const m of memberships) {
    if (!best || rank[m.role_in_team] > rank[best]) best = m.role_in_team;
  }

  const teamRoles = await query(
    "SELECT id, slug FROM roles WHERE company_id IS NULL AND slug IN ('team-lead','assistant-team-lead','team-member')"
  );
  const idBySlug = new Map(teamRoles.map((r) => [r.slug, r.id]));
  const allTeamRoleIds = teamRoles.map((r) => r.id);

  // Remove all team-level role assignments, then add the one that matches.
  // (All-positional placeholders — do not mix with named in one statement.)
  if (allTeamRoleIds.length) {
    await execute(
      `DELETE FROM user_roles WHERE user_id = ? AND role_id IN (${allTeamRoleIds.map(() => '?').join(',')})`,
      [userId, ...allTeamRoleIds]
    );
  }
  if (best) {
    const roleId = idBySlug.get(TEAM_ROLE_SLUG[best]);
    if (roleId) {
      await execute('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (:u, :r)', { u: userId, r: roleId });
    }
  }
  permissionService.invalidateUser(userId);
}

// GET /company/users — lightweight roster (id/name/email) for assignee & filter
// pickers. Available to anyone who can create/assign/oversee tasks.
const companyUsers = asyncHandler(async (req, res) => {
  const companyId = scope(req);
  if (!companyId) return res.json({ users: [] });
  const rows = await query(
    `SELECT id, name, email FROM users
      WHERE company_id = :c AND deleted_at IS NULL AND is_super_admin = 0 AND status = 'active'
      ORDER BY name`,
    { c: companyId }
  );
  res.json({ users: rows });
});

// GET /me/teams — the teams the current user belongs to, with their role.
// Available to ANY authenticated user (no team.view needed) so a plain member
// can see their own memberships on the dashboard.
const myTeams = asyncHandler(async (req, res) => {
  const rows = await query(
    `SELECT t.id, t.name, m.role_in_team
       FROM team_members m
       JOIN teams t ON t.id = m.team_id AND t.deleted_at IS NULL
      WHERE m.user_id = :u
      ORDER BY FIELD(m.role_in_team,'lead','assistant_lead','member'), t.name`,
    { u: req.user.id }
  );
  res.json({ teams: rows });
});

// GET /teams
const list = asyncHandler(async (req, res) => {
  const companyId = scope(req);
  const rows = await query(
    `SELECT t.*,
            (SELECT COUNT(*) FROM team_members m WHERE m.team_id = t.id) AS member_count,
            (SELECT u.name FROM team_members m JOIN users u ON u.id = m.user_id
              WHERE m.team_id = t.id AND m.role_in_team = 'lead' LIMIT 1) AS lead_name
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
  const members = await query('SELECT user_id FROM team_members WHERE team_id = :t', { t: team.id });
  await execute('UPDATE teams SET deleted_at = NOW() WHERE id = :id', { id: team.id });
  await execute('DELETE FROM team_members WHERE team_id = :id', { id: team.id });
  for (const m of members) await syncTeamRbacRole(m.user_id);
  await audit.record({ actor: req.user, action: 'team.delete', entityType: 'team', entityId: team.id, companyId: team.company_id, ip: clientIp(req) });
  res.json({ ok: true });
});

// GET /teams/:id/members
const members = asyncHandler(async (req, res) => {
  const team = await loadTeamScoped(req);
  const rows = await query(
    `SELECT u.id, u.name, u.email, m.role_in_team
       FROM team_members m JOIN users u ON u.id = m.user_id
      WHERE m.team_id = :t
      ORDER BY FIELD(m.role_in_team,'lead','assistant_lead','member'), u.name`,
    { t: team.id }
  );
  res.json({ members: rows });
});

// POST /teams/:id/members  { userId, roleInTeam? }
const addMember = asyncHandler(async (req, res) => {
  const team = await loadTeamScoped(req);
  await assertCanManageTeam(req, team);
  const { userId, roleInTeam = 'member' } = req.body || {};
  if (!['lead', 'assistant_lead', 'member'].includes(roleInTeam)) {
    return res.status(400).json({ error: 'invalid roleInTeam' });
  }
  // Only company admins / lead-managers may seat a lead or assistant lead.
  if (roleInTeam !== 'member') {
    const canManageLeads = req.user.is_super_admin || await permissionService.can(req.user.id, 'team.manage_leads');
    if (!canManageLeads) return res.status(403).json({ error: 'Requires team.manage_leads to seat a lead/assistant' });
  }
  const u = await queryOne('SELECT id, company_id FROM users WHERE id = :id AND deleted_at IS NULL', { id: userId });
  if (!u) return res.status(404).json({ error: 'User not found' });
  if (Number(u.company_id) !== Number(team.company_id)) return res.status(400).json({ error: 'User is in another company' });

  await execute(
    `INSERT INTO team_members (team_id, user_id, role_in_team) VALUES (:t, :u, :r)
     ON DUPLICATE KEY UPDATE role_in_team = VALUES(role_in_team)`,
    { t: team.id, u: userId, r: roleInTeam }
  );
  await syncTeamRbacRole(userId);
  await audit.record({ actor: req.user, action: 'team.add_member', entityType: 'team', entityId: team.id, targetUserId: userId, companyId: team.company_id, changes: { roleInTeam }, ip: clientIp(req) });
  res.json({ ok: true });
});

// PUT /teams/:id/members/:userId/role  { roleInTeam }
const setMemberRole = asyncHandler(async (req, res) => {
  const team = await loadTeamScoped(req);
  const { roleInTeam } = req.body || {};
  if (!['lead', 'assistant_lead', 'member'].includes(roleInTeam)) {
    return res.status(400).json({ error: 'invalid roleInTeam' });
  }
  const exists = await queryOne('SELECT user_id FROM team_members WHERE team_id = :t AND user_id = :u', { t: team.id, u: req.params.userId });
  if (!exists) return res.status(404).json({ error: 'User is not a member of this team' });
  await execute('UPDATE team_members SET role_in_team = :r WHERE team_id = :t AND user_id = :u', { r: roleInTeam, t: team.id, u: req.params.userId });
  await syncTeamRbacRole(Number(req.params.userId));
  await audit.record({ actor: req.user, action: 'team.set_member_role', entityType: 'team', entityId: team.id, targetUserId: Number(req.params.userId), companyId: team.company_id, changes: { roleInTeam }, ip: clientIp(req) });
  res.json({ ok: true });
});

// DELETE /teams/:id/members/:userId
const removeMember = asyncHandler(async (req, res) => {
  const team = await loadTeamScoped(req);
  await assertCanManageTeam(req, team);
  await execute('DELETE FROM team_members WHERE team_id = :t AND user_id = :u', { t: team.id, u: req.params.userId });
  await syncTeamRbacRole(Number(req.params.userId));
  await audit.record({ actor: req.user, action: 'team.remove_member', entityType: 'team', entityId: team.id, targetUserId: Number(req.params.userId), companyId: team.company_id, ip: clientIp(req) });
  res.json({ ok: true });
});

// GET /teams/:id/members/:userId/access
// The current effect of each grantable permission for a member (for the lead UI).
const memberAccess = asyncHandler(async (req, res) => {
  const team = await loadTeamScoped(req);
  const eff = await permissionService.effectiveForUi(req.params.userId);
  const byKey = new Map();
  for (const g of eff.groups) for (const p of g.permissions) byKey.set(p.key, p);
  const items = GRANTABLE_MEMBER_PERMS.map((key) => {
    const p = byKey.get(key) || {};
    return { key, label: p.label || key, override: p.override || null, allowed: !!p.allowed, locked: !!p.locked };
  });
  res.json({ userId: Number(req.params.userId), team: { id: team.id, name: team.name }, permissions: items });
});

// PUT /teams/:id/members/:userId/access  { grants: { 'task.create': 'allow'|'deny'|'inherit', ... } }
const setMemberAccess = asyncHandler(async (req, res) => {
  const team = await loadTeamScoped(req);
  await assertCanManageTeam(req, team);
  const membership = await queryOne('SELECT user_id FROM team_members WHERE team_id = :t AND user_id = :u', { t: team.id, u: req.params.userId });
  if (!membership) return res.status(404).json({ error: 'User is not a member of this team' });

  const grants = (req.body && req.body.grants) || {};
  const changed = {};
  for (const [key, effect] of Object.entries(grants)) {
    if (!GRANTABLE_MEMBER_PERMS.includes(key)) continue;
    const perm = await queryOne('SELECT id FROM permissions WHERE `key` = :k', { k: key });
    if (!perm) continue;
    if (effect === 'inherit' || effect == null) {
      await execute('DELETE FROM user_permissions WHERE user_id = :u AND permission_id = :p', { u: req.params.userId, p: perm.id });
    } else if (effect === 'allow' || effect === 'deny') {
      await execute(
        `INSERT INTO user_permissions (user_id, permission_id, effect) VALUES (:u, :p, :e)
         ON DUPLICATE KEY UPDATE effect = VALUES(effect)`,
        { u: req.params.userId, p: perm.id, e: effect }
      );
    }
    changed[key] = effect;
  }
  permissionService.invalidateUser(Number(req.params.userId));
  await audit.record({ actor: req.user, action: 'team.grant_member_perms', entityType: 'user', entityId: Number(req.params.userId), targetUserId: Number(req.params.userId), companyId: team.company_id, changes: changed, ip: clientIp(req) });
  res.json({ ok: true, changed });
});

// ---- Task-list access ("let X see Y's task list") --------------------------
// GET /task-access?ownerId= | ?viewerId=
const listAccess = asyncHandler(async (req, res) => {
  const companyId = scope(req);
  const where = ['company_id = :c'];
  const params = { c: companyId };
  if (req.query.ownerId) { where.push('owner_id = :o'); params.o = Number(req.query.ownerId); }
  if (req.query.viewerId) { where.push('viewer_id = :v'); params.v = Number(req.query.viewerId); }
  const rows = await query(
    `SELECT tls.owner_id, tls.viewer_id, o.name AS owner_name, v.name AS viewer_name, tls.created_at
       FROM task_list_shares tls
       JOIN users o ON o.id = tls.owner_id
       JOIN users v ON v.id = tls.viewer_id
      WHERE ${where.join(' AND ')} ORDER BY tls.created_at DESC`,
    params
  );
  res.json({ grants: rows });
});

// POST /task-access  { ownerId, viewerId }
const grantAccess = asyncHandler(async (req, res) => {
  const companyId = scope(req);
  const { ownerId, viewerId } = req.body || {};
  if (!ownerId || !viewerId) return res.status(400).json({ error: 'ownerId and viewerId are required' });
  if (Number(ownerId) === Number(viewerId)) return res.status(400).json({ error: 'owner and viewer are the same user' });
  for (const id of [ownerId, viewerId]) {
    const u = await queryOne('SELECT id FROM users WHERE id = :id AND company_id = :c AND deleted_at IS NULL', { id, c: companyId });
    if (!u) return res.status(400).json({ error: 'Both users must be in your company' });
  }
  await execute(
    `INSERT INTO task_list_shares (company_id, owner_id, viewer_id, granted_by) VALUES (:c, :o, :v, :g)
     ON DUPLICATE KEY UPDATE granted_by = VALUES(granted_by)`,
    { c: companyId, o: ownerId, v: viewerId, g: req.user.id }
  );
  await audit.record({ actor: req.user, action: 'task.list_share', entityType: 'user', entityId: Number(ownerId), targetUserId: Number(viewerId), companyId, changes: { ownerId, viewerId }, ip: clientIp(req) });
  res.json({ ok: true });
});

// DELETE /task-access/:ownerId/:viewerId
const revokeAccess = asyncHandler(async (req, res) => {
  const companyId = scope(req);
  await execute(
    'DELETE FROM task_list_shares WHERE company_id = :c AND owner_id = :o AND viewer_id = :v',
    { c: companyId, o: req.params.ownerId, v: req.params.viewerId }
  );
  res.json({ ok: true });
});

module.exports = {
  companyUsers, myTeams,
  list, create, remove, members, addMember, setMemberRole, removeMember,
  memberAccess, setMemberAccess,
  listAccess, grantAccess, revokeAccess,
};
