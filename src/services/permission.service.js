'use strict';

/**
 * ============================================================================
 *  PERMISSION ENGINE
 * ============================================================================
 * Computes a user's *effective* permissions by combining, in strict priority:
 *
 *   1. Super Admin           -> always ALLOW (short-circuit)
 *   2. System-only guard     -> is_system permissions are super-admin only
 *   3. Company boundary       -> company DENY disables a permission company-wide
 *   4. User override (deny)   -> explicit user DENY
 *   5. User override (allow)  -> explicit user ALLOW (adds beyond role)
 *   6. Role permission        -> any assigned role grants it
 *   7. Default                -> DENY (nothing grants it)
 *
 * Every decision carries a human-readable `source` for the UI (permission
 * inheritance / effective-permissions views).
 *
 * Results are cached in-memory per user and invalidated on any change. Swap
 * `cache` for Redis in a multi-process deployment.
 */

const { query, queryOne } = require('../config/db');

// ---- simple in-process cache (userId -> computed result) -------------------
const cache = new Map();

function invalidateUser(userId) {
  cache.delete(Number(userId));
}
function invalidateAll() {
  cache.clear();
}
/** Invalidate every user in a company (e.g. company boundary changed). */
async function invalidateCompany(companyId) {
  const users = await query('SELECT id FROM users WHERE company_id = :c', { c: companyId });
  users.forEach((u) => cache.delete(Number(u.id)));
}
/** Invalidate every user holding a given role (role permissions changed). */
async function invalidateRole(roleId) {
  const users = await query('SELECT user_id FROM user_roles WHERE role_id = :r', { r: roleId });
  users.forEach((u) => cache.delete(Number(u.user_id)));
}

const SOURCE = {
  SUPER_ADMIN: 'Super Admin',
  SYSTEM_POLICY: 'System Policy',
  COMPANY_POLICY: 'Company Policy',
  USER_OVERRIDE: 'User Override',
  ROLE: 'Role',
  DEFAULT: 'Not assigned',
};

async function loadUser(userId) {
  return queryOne(
    `SELECT id, company_id, name, email, status, is_super_admin
       FROM users WHERE id = :id AND deleted_at IS NULL`,
    { id: userId }
  );
}

/**
 * Build the full effective-permission map for a user.
 * Returns { user, isSuperAdmin, permissions: Map<key, decision>, roles, summary }
 * where decision = { key, allowed, source, sourceDetail }.
 */
async function computeEffective(userId) {
  const cached = cache.get(Number(userId));
  if (cached) return cached;

  const user = await loadUser(userId);
  if (!user) throw Object.assign(new Error('User not found'), { status: 404 });

  // The full permission catalog (needed so we can report a decision for each).
  const allPerms = await query(
    'SELECT id, `key`, action, group_id, label, is_system FROM permissions'
  );

  const decisions = new Map();

  // ---- Super Admin short-circuit ----
  if (user.is_super_admin) {
    for (const p of allPerms) {
      decisions.set(p.key, {
        key: p.key, allowed: true, source: SOURCE.SUPER_ADMIN, sourceDetail: null,
        override: null, base: { allowed: true, source: SOURCE.SUPER_ADMIN, sourceDetail: null }, locked: true,
      });
    }
    const result = finalize(user, [], decisions, true);
    cache.set(Number(userId), result);
    return result;
  }

  // ---- Load the inputs for a normal user ----
  const roles = await query(
    `SELECT r.id, r.name, r.slug FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = :u`,
    { u: userId }
  );
  const roleIds = roles.map((r) => r.id);

  // role -> permission (remember which role granted, for source detail)
  const grantedByRole = new Map(); // permissionId -> roleName
  if (roleIds.length) {
    const rows = await query(
      `SELECT rp.permission_id, r.name AS role_name
         FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
        WHERE rp.role_id IN (${roleIds.map(() => '?').join(',')})
        ORDER BY r.name`,
      roleIds
    );
    for (const row of rows) {
      if (!grantedByRole.has(row.permission_id)) grantedByRole.set(row.permission_id, row.role_name);
    }
  }

  // user overrides: permissionId -> 'allow' | 'deny'
  const overrides = new Map();
  const upRows = await query(
    'SELECT permission_id, effect FROM user_permissions WHERE user_id = :u', { u: userId }
  );
  upRows.forEach((r) => overrides.set(r.permission_id, r.effect));

  // company boundary: permissionId set that is DISABLED for the company
  const companyDeny = new Set();
  if (user.company_id) {
    const cpRows = await query(
      "SELECT permission_id FROM company_permissions WHERE company_id = :c AND effect = 'deny'",
      { c: user.company_id }
    );
    cpRows.forEach((r) => companyDeny.add(r.permission_id));
  }

  // ---- Evaluate every permission ----
  for (const p of allPerms) {
    const ov = overrides.get(p.id) || null; // 'allow' | 'deny' | null

    // base = the decision WITHOUT the user override (role / company / system).
    let base;
    if (p.is_system) base = { allowed: false, source: SOURCE.SYSTEM_POLICY, sourceDetail: 'Super-admin only' };
    else if (companyDeny.has(p.id)) base = { allowed: false, source: SOURCE.COMPANY_POLICY, sourceDetail: 'Disabled for company' };
    else if (grantedByRole.has(p.id)) base = { allowed: true, source: SOURCE.ROLE, sourceDetail: grantedByRole.get(p.id) };
    else base = { allowed: false, source: SOURCE.DEFAULT, sourceDetail: null };

    let decision;
    if (p.is_system) {
      // system permissions can never be granted to a normal user
      decision = { key: p.key, allowed: false, source: SOURCE.SYSTEM_POLICY, sourceDetail: 'Super-admin only' };
    } else if (companyDeny.has(p.id)) {
      // company boundary is a hard ceiling — it wins over any user override
      decision = { key: p.key, allowed: false, source: SOURCE.COMPANY_POLICY, sourceDetail: 'Disabled for company' };
    } else if (ov === 'deny') {
      decision = { key: p.key, allowed: false, source: SOURCE.USER_OVERRIDE, sourceDetail: 'Explicit deny' };
    } else if (ov === 'allow') {
      decision = { key: p.key, allowed: true, source: SOURCE.USER_OVERRIDE, sourceDetail: 'Explicit allow' };
    } else {
      decision = { key: p.key, allowed: base.allowed, source: base.source, sourceDetail: base.sourceDetail };
    }
    // Expose override + base so the UI can preview "inherit" live and lock
    // permissions the company boundary forbids.
    decision.override = ov;
    decision.base = base;
    decision.locked = p.is_system || companyDeny.has(p.id);
    decisions.set(p.key, decision);
  }

  const result = finalize(user, roles, decisions, false);
  cache.set(Number(userId), result);
  return result;
}

function finalize(user, roles, decisions, isSuperAdmin) {
  let allowed = 0, denied = 0, roleCount = 0, overrideCount = 0, companyRestrictions = 0;
  for (const d of decisions.values()) {
    if (d.allowed) allowed += 1; else denied += 1;
    if (d.source === SOURCE.ROLE) roleCount += 1;
    if (d.source === SOURCE.USER_OVERRIDE) overrideCount += 1;
    if (d.source === SOURCE.COMPANY_POLICY) companyRestrictions += 1;
  }
  return {
    user: {
      id: user.id, name: user.name, email: user.email,
      company_id: user.company_id, status: user.status, is_super_admin: !!user.is_super_admin,
    },
    isSuperAdmin,
    roles,
    permissions: decisions,
    summary: {
      total: decisions.size,
      allowed,
      denied,
      rolePermissions: roleCount,
      userOverrides: overrideCount,
      companyRestrictions,
    },
  };
}

// ---- Public helpers --------------------------------------------------------

/** Boolean check used by the `can()` middleware. */
async function can(userId, permissionKey) {
  const eff = await computeEffective(userId);
  const d = eff.permissions.get(permissionKey);
  return !!(d && d.allowed);
}

/** can() for any-of a list. */
async function canAny(userId, keys) {
  const eff = await computeEffective(userId);
  return keys.some((k) => eff.permissions.get(k)?.allowed);
}

/**
 * Simulation: explain a single decision (permission preview feature).
 * Returns { allowed, source, sourceDetail, reason }.
 */
async function simulate(userId, permissionKey) {
  const eff = await computeEffective(userId);
  const d = eff.permissions.get(permissionKey);
  if (!d) return { allowed: false, source: 'Unknown', reason: `Unknown permission: ${permissionKey}` };

  const reasonMap = {
    [SOURCE.SUPER_ADMIN]: 'User is a Super Admin — always allowed.',
    [SOURCE.SYSTEM_POLICY]: 'System-level permission, restricted to Super Admin.',
    [SOURCE.COMPANY_POLICY]: 'Denied by company policy (disabled for this company).',
    [SOURCE.USER_OVERRIDE]: d.allowed
      ? 'Granted by a user-specific permission override (ALLOW).'
      : 'Blocked by a user-specific permission override (DENY).',
    [SOURCE.ROLE]: `Granted by role: ${d.sourceDetail}.`,
    [SOURCE.DEFAULT]: 'Permission is not assigned by any role or override.',
  };
  return {
    userId: Number(userId),
    permission: permissionKey,
    allowed: d.allowed,
    source: d.source,
    sourceDetail: d.sourceDetail,
    reason: reasonMap[d.source] || (d.allowed ? 'Allowed.' : 'Denied.'),
  };
}

/**
 * Effective permissions as a plain, UI-friendly array grouped by module.
 */
async function effectiveForUi(userId) {
  const eff = await computeEffective(userId);
  const perms = await query(
    `SELECT p.\`key\`, p.action, p.label, p.is_system,
            g.\`key\` AS group_key, g.label AS group_label, g.sort_order
       FROM permissions p JOIN permission_groups g ON g.id = p.group_id
      ORDER BY g.sort_order, p.id`
  );
  const groups = new Map();
  for (const p of perms) {
    const d = eff.permissions.get(p.key);
    if (!groups.has(p.group_key)) {
      groups.set(p.group_key, { key: p.group_key, label: p.group_label, permissions: [] });
    }
    groups.get(p.group_key).permissions.push({
      key: p.key,
      action: p.action,
      label: p.label,
      isSystem: !!p.is_system,
      allowed: !!(d && d.allowed),
      source: d ? d.source : SOURCE.DEFAULT,
      sourceDetail: d ? d.sourceDetail : null,
      override: d ? d.override : null,     // 'allow' | 'deny' | null
      base: d ? d.base : null,             // decision without user override
      locked: d ? !!d.locked : false,      // company/system forbids editing
    });
  }
  return {
    user: eff.user,
    isSuperAdmin: eff.isSuperAdmin,
    roles: eff.roles,
    summary: eff.summary,
    groups: Array.from(groups.values()),
    // flat allowed keys, handy for the frontend to gate UI
    allowedKeys: Array.from(eff.permissions.values()).filter((d) => d.allowed).map((d) => d.key),
  };
}

module.exports = {
  computeEffective,
  effectiveForUi,
  can,
  canAny,
  simulate,
  invalidateUser,
  invalidateAll,
  invalidateCompany,
  invalidateRole,
  SOURCE,
};
