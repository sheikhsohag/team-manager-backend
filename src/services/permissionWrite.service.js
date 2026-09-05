'use strict';

/**
 * All *mutations* to the permission model live here so that every change:
 *   (a) is written atomically,
 *   (b) invalidates the effective-permission cache, and
 *   (c) is recorded in the audit log (permission change history).
 */

const { query, execute, transaction } = require('../config/db');
const permissionService = require('./permission.service');
const audit = require('./audit.service');

async function permMaps() {
  const rows = await query('SELECT id, `key` FROM permissions');
  const byKey = new Map(rows.map((r) => [r.key, r.id]));
  const byId = new Map(rows.map((r) => [r.id, r.key]));
  return { byKey, byId };
}

/**
 * Apply per-permission overrides for a user.
 * changes: [{ key, effect }] where effect is 'allow' | 'deny' | 'inherit'.
 * 'inherit' removes any existing override for that permission.
 */
async function setUserOverrides(actor, targetUserId, changes, ip) {
  const { byKey } = await permMaps();

  // current overrides for diffing
  const currentRows = await query(
    'SELECT permission_id, effect FROM user_permissions WHERE user_id = :u', { u: targetUserId }
  );
  const current = new Map(currentRows.map((r) => [r.permission_id, r.effect]));

  const added = [], removed = [], changed = [];

  await transaction(async (t) => {
    for (const ch of changes) {
      const pid = byKey.get(ch.key);
      if (!pid) continue;
      const prev = current.get(pid);

      if (ch.effect === 'inherit') {
        if (prev) {
          await t.execute(
            'DELETE FROM user_permissions WHERE user_id = :u AND permission_id = :p',
            { u: targetUserId, p: pid }
          );
          removed.push({ key: ch.key, was: prev });
        }
        continue;
      }
      if (ch.effect !== 'allow' && ch.effect !== 'deny') continue;

      if (!prev) {
        added.push({ key: ch.key, effect: ch.effect });
      } else if (prev !== ch.effect) {
        changed.push({ key: ch.key, from: prev, to: ch.effect });
      } else {
        continue; // no change
      }
      await t.execute(
        `INSERT INTO user_permissions (user_id, permission_id, effect) VALUES (:u, :p, :e)
         ON DUPLICATE KEY UPDATE effect = VALUES(effect)`,
        { u: targetUserId, p: pid, e: ch.effect }
      );
    }
  });

  permissionService.invalidateUser(targetUserId);

  if (added.length || removed.length || changed.length) {
    await audit.record({
      actor, action: 'permissions.update', entityType: 'user',
      entityId: targetUserId, targetUserId,
      changes: { added, removed, changed }, ip,
    });
  }
  return { added, removed, changed };
}

/** Remove all user overrides — reset the user to pure role defaults. */
async function resetUserToRole(actor, targetUserId, ip) {
  const before = await query(
    `SELECT p.\`key\`, up.effect FROM user_permissions up
       JOIN permissions p ON p.id = up.permission_id WHERE up.user_id = :u`,
    { u: targetUserId }
  );
  await execute('DELETE FROM user_permissions WHERE user_id = :u', { u: targetUserId });
  permissionService.invalidateUser(targetUserId);
  await audit.record({
    actor, action: 'permissions.reset_to_role', entityType: 'user',
    entityId: targetUserId, targetUserId, changes: { removedOverrides: before }, ip,
  });
  return { removed: before.length };
}

/**
 * Copy user overrides from one user to another (Copy Permissions feature).
 * Replaces the target's overrides with the source's.
 */
async function copyUserPermissions(actor, fromUserId, toUserId, ip) {
  const source = await query(
    'SELECT permission_id, effect FROM user_permissions WHERE user_id = :u', { u: fromUserId }
  );
  await transaction(async (t) => {
    await t.execute('DELETE FROM user_permissions WHERE user_id = :u', { u: toUserId });
    for (const row of source) {
      await t.execute(
        'INSERT INTO user_permissions (user_id, permission_id, effect) VALUES (:u, :p, :e)',
        { u: toUserId, p: row.permission_id, e: row.effect }
      );
    }
  });
  permissionService.invalidateUser(toUserId);
  await audit.record({
    actor, action: 'permissions.copy', entityType: 'user', entityId: toUserId,
    targetUserId: toUserId, changes: { fromUserId: Number(fromUserId), copied: source.length }, ip,
  });
  return { copied: source.length };
}

/** Replace a role's permission set. */
async function setRolePermissions(actor, roleId, permissionKeys, ip) {
  const { byKey } = await permMaps();
  const before = await query(
    `SELECT p.\`key\` FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
      WHERE rp.role_id = :r`, { r: roleId }
  );
  const beforeSet = new Set(before.map((r) => r.key));
  const afterSet = new Set(permissionKeys.filter((k) => byKey.has(k)));

  await transaction(async (t) => {
    await t.execute('DELETE FROM role_permissions WHERE role_id = :r', { r: roleId });
    for (const key of afterSet) {
      await t.execute(
        'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (:r, :p)',
        { r: roleId, p: byKey.get(key) }
      );
    }
  });

  await permissionService.invalidateRole(roleId);
  await audit.record({
    actor, action: 'role.permissions.update', entityType: 'role', entityId: roleId,
    changes: {
      added: [...afterSet].filter((k) => !beforeSet.has(k)),
      removed: [...beforeSet].filter((k) => !afterSet.has(k)),
    }, ip,
  });
}

/**
 * Set the company boundary. `disabledKeys` = permissions DISABLED company-wide.
 */
async function setCompanyBoundary(actor, companyId, disabledKeys, ip) {
  const { byKey } = await permMaps();
  const before = await query(
    `SELECT p.\`key\` FROM company_permissions cp JOIN permissions p ON p.id = cp.permission_id
      WHERE cp.company_id = :c AND cp.effect = 'deny'`, { c: companyId }
  );
  const beforeSet = new Set(before.map((r) => r.key));
  const afterSet = new Set(disabledKeys.filter((k) => byKey.has(k)));

  await transaction(async (t) => {
    await t.execute("DELETE FROM company_permissions WHERE company_id = :c AND effect = 'deny'", { c: companyId });
    for (const key of afterSet) {
      await t.execute(
        `INSERT INTO company_permissions (company_id, permission_id, effect) VALUES (:c, :p, 'deny')
         ON DUPLICATE KEY UPDATE effect = 'deny'`,
        { c: companyId, p: byKey.get(key) }
      );
    }
  });

  await permissionService.invalidateCompany(companyId);
  await audit.record({
    actor, action: 'company.permissions.update', entityType: 'company', entityId: companyId, companyId,
    changes: {
      disabled: [...afterSet].filter((k) => !beforeSet.has(k)),
      enabled: [...beforeSet].filter((k) => !afterSet.has(k)),
    }, ip,
  });
}

/** Apply a template to a user as ALLOW overrides. mode: 'replace' | 'merge'. */
async function applyTemplateToUser(actor, targetUserId, templateId, mode = 'merge', ip) {
  const keys = await query(
    `SELECT p.\`key\` FROM permission_template_items i JOIN permissions p ON p.id = i.permission_id
      WHERE i.template_id = :t`, { t: templateId }
  );
  const changes = keys.map((r) => ({ key: r.key, effect: 'allow' }));
  if (mode === 'replace') {
    await resetUserToRole(actor, targetUserId, ip);
  }
  const result = await setUserOverrides(actor, targetUserId, changes, ip);
  await audit.record({
    actor, action: 'permissions.apply_template', entityType: 'user', entityId: targetUserId,
    targetUserId, changes: { templateId: Number(templateId), mode, applied: changes.length }, ip,
  });
  return result;
}

/** Bulk: assign a role to many users. */
async function bulkAssignRole(actor, userIds, roleId, ip) {
  await transaction(async (t) => {
    for (const uid of userIds) {
      await t.execute('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (:u, :r)', { u: uid, r: roleId });
    }
  });
  userIds.forEach((uid) => permissionService.invalidateUser(uid));
  await audit.record({
    actor, action: 'bulk.assign_role', entityType: 'role', entityId: roleId,
    changes: { userIds, roleId: Number(roleId) }, ip,
  });
}

/** Bulk: add or remove a single permission override for many users. */
async function bulkSetPermission(actor, userIds, key, effect, ip) {
  const changes = [{ key, effect }];
  for (const uid of userIds) {
    await setUserOverrides(actor, uid, changes, ip);
  }
  await audit.record({
    actor, action: 'bulk.set_permission', entityType: 'permission',
    changes: { userIds, key, effect }, ip,
  });
}

module.exports = {
  setUserOverrides,
  resetUserToRole,
  copyUserPermissions,
  setRolePermissions,
  setCompanyBoundary,
  applyTemplateToUser,
  bulkAssignRole,
  bulkSetPermission,
};
