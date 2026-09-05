'use strict';

const { query } = require('../config/db');
const permissionService = require('../services/permission.service');
const permissionWrite = require('../services/permissionWrite.service');
const { asyncHandler } = require('../middleware/error');
const { clientIp, getUserOr404, assertCanManageUser, parseList } = require('./helpers');

// GET /permissions — the full catalog, grouped by module (for building matrices)
const catalog = asyncHandler(async (req, res) => {
  const rows = await query(
    `SELECT p.id, p.\`key\`, p.action, p.label, p.description, p.is_system,
            g.\`key\` AS group_key, g.label AS group_label, g.sort_order
       FROM permissions p JOIN permission_groups g ON g.id = p.group_id
      ORDER BY g.sort_order, p.id`
  );
  const groups = new Map();
  const actionsSet = new Set();
  for (const p of rows) {
    if (!groups.has(p.group_key)) {
      groups.set(p.group_key, { key: p.group_key, label: p.group_label, permissions: [] });
    }
    groups.get(p.group_key).permissions.push({
      key: p.key, action: p.action, label: p.label,
      description: p.description, isSystem: !!p.is_system,
    });
    if (!p.is_system) actionsSet.add(p.action);
  }
  res.json({ groups: Array.from(groups.values()), actions: Array.from(actionsSet) });
});

// POST /permissions/simulate  { userId, permission }  -> preview / debug a decision
const simulate = asyncHandler(async (req, res) => {
  const { userId, permission } = req.body || {};
  if (!userId || !permission) return res.status(400).json({ error: 'userId and permission are required' });
  const target = await getUserOr404(userId);
  // A non-super actor may only simulate users in their own company.
  if (!req.user.is_super_admin && Number(target.company_id) !== Number(req.user.company_id)) {
    return res.status(403).json({ error: 'Cross-company access denied' });
  }
  const result = await permissionService.simulate(userId, permission);
  res.json(result);
});

// POST /permissions/copy  { fromUserId, toUserId }
const copy = asyncHandler(async (req, res) => {
  const { fromUserId, toUserId } = req.body || {};
  if (!fromUserId || !toUserId) return res.status(400).json({ error: 'fromUserId and toUserId are required' });
  const from = await getUserOr404(fromUserId);
  const to = await getUserOr404(toUserId);
  assertCanManageUser(req.user, from);
  assertCanManageUser(req.user, to);
  const result = await permissionWrite.copyUserPermissions(req.user, fromUserId, toUserId, clientIp(req));
  res.json(result);
});

// POST /permissions/bulk
//   { userIds: [], action: 'assign_role'|'add_permission'|'remove_permission', roleId?, key? }
const bulk = asyncHandler(async (req, res) => {
  const { userIds: raw, action, roleId, key } = req.body || {};
  const userIds = parseList(raw).map(Number).filter(Boolean);
  if (!userIds.length) return res.status(400).json({ error: 'userIds is required' });

  // company boundary: verify every target is manageable
  for (const uid of userIds) {
    const u = await getUserOr404(uid);
    assertCanManageUser(req.user, u);
  }

  const ip = clientIp(req);
  if (action === 'assign_role') {
    if (!roleId) return res.status(400).json({ error: 'roleId is required' });
    await permissionWrite.bulkAssignRole(req.user, userIds, roleId, ip);
  } else if (action === 'add_permission') {
    if (!key) return res.status(400).json({ error: 'key is required' });
    await permissionWrite.bulkSetPermission(req.user, userIds, key, 'allow', ip);
  } else if (action === 'remove_permission') {
    if (!key) return res.status(400).json({ error: 'key is required' });
    await permissionWrite.bulkSetPermission(req.user, userIds, key, 'deny', ip);
  } else {
    return res.status(400).json({ error: 'Unknown bulk action' });
  }
  res.json({ ok: true, affected: userIds.length });
});

module.exports = { catalog, simulate, copy, bulk };
