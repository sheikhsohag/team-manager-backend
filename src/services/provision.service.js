'use strict';

/**
 * Company provisioning helpers shared by the seeder and self-registration.
 */

const catalog = require('../db/seed/catalog');

// Permissions an INDIVIDUAL (solo) workspace should never have. Applied as a
// company-boundary DENY, which the permission engine treats as a hard ceiling
// (wins over role + user override) and which the owner cannot lift themselves.
const INDIVIDUAL_DENIED_KEYS = [
  // company management
  'company.view', 'company.update', 'company.permissions',
  // teams / members
  'team.view', 'team.create', 'team.update', 'team.delete',
  'team.add_member', 'team.remove_member', 'team.manage_leads', 'team.grant_member_perms',
  // other users & admins
  'user.view', 'user.create', 'user.update', 'user.delete',
  'user.suspend', 'user.restore', 'user.reset_password',
  'admin.view', 'admin.create', 'admin.update', 'admin.delete', 'admin.permissions',
  // company-wide / cross-user task facilities that only make sense with a team
  'task.view_all', 'task.share',
];

/**
 * Insert the default dynamic statuses for a company (idempotent per name).
 * `exec` is a query runner: (sql, params) => Promise  (the db `execute` helper
 * or a transaction's `execute`).
 */
async function seedCompanyStatuses(exec, companyId, createdBy = null) {
  for (const [name, note, color, sort, isDefault, isDone] of catalog.DEFAULT_STATUSES) {
    await exec(
      `INSERT INTO task_statuses (company_id, name, note, color, sort_order, is_default, is_done, created_by)
       VALUES (:c, :n, :note, :color, :sort, :def, :done, :by)
       ON DUPLICATE KEY UPDATE note = VALUES(note)`,
      { c: companyId, n: name, note, color, sort, def: isDefault, done: isDone, by: createdBy }
    );
  }
}

/**
 * Apply the individual-account permission ceiling to a company. `exec` is a
 * query runner (db.execute or a transaction's execute); `q` runs a SELECT.
 */
async function applyIndividualBoundary(exec, q, companyId) {
  const placeholders = INDIVIDUAL_DENIED_KEYS.map(() => '?').join(',');
  const perms = await q(
    `SELECT id FROM permissions WHERE \`key\` IN (${placeholders})`,
    INDIVIDUAL_DENIED_KEYS
  );
  for (const p of perms) {
    await exec(
      `INSERT INTO company_permissions (company_id, permission_id, effect) VALUES (:c, :p, 'deny')
       ON DUPLICATE KEY UPDATE effect = 'deny'`,
      { c: companyId, p: p.id }
    );
  }
}

module.exports = { seedCompanyStatuses, applyIndividualBoundary, INDIVIDUAL_DENIED_KEYS };
