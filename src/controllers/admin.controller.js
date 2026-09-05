'use strict';

const { query } = require('../config/db');
const permissionService = require('../services/permission.service');
const { asyncHandler } = require('../middleware/error');

/**
 * GET /super-admin/admins — the Admin Management table.
 * Returns admins (users with an admin/manager-level role) with their live
 * allowed/denied permission counts computed by the engine.
 */
const listAdmins = asyncHandler(async (req, res) => {
  const params = {};
  const where = ["u.deleted_at IS NULL", "u.is_super_admin = 0"];
  if (!req.user.is_super_admin) { where.push('u.company_id = :c'); params.c = req.user.company_id; }
  if (req.query.companyId) { where.push('u.company_id = :companyId'); params.companyId = req.query.companyId; }

  // "Admins" = users holding a company-level role (admin/manager). Filter in app.
  const rows = await query(
    `SELECT u.id, u.name, u.email, u.status, u.company_id,
            c.name AS company_name,
            GROUP_CONCAT(DISTINCT r.name ORDER BY r.name SEPARATOR ', ') AS role_names,
            MAX(CASE WHEN r.level IN ('company') THEN 1 ELSE 0 END) AS is_company_role
       FROM users u
       LEFT JOIN companies c ON c.id = u.company_id
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
      WHERE ${where.join(' AND ')}
      GROUP BY u.id
      ORDER BY c.name, u.name`,
    params
  );

  const admins = [];
  for (const r of rows) {
    // Only surface users that carry a company-level (admin/manager) role.
    if (!r.is_company_role) continue;
    const eff = await permissionService.computeEffective(r.id);
    admins.push({
      id: r.id,
      name: r.name,
      email: r.email,
      status: r.status,
      companyId: r.company_id,
      company: r.company_name,
      role: r.role_names,
      permissions: {
        allowed: eff.summary.allowed,
        denied: eff.summary.denied,
        overrides: eff.summary.userOverrides,
        companyRestrictions: eff.summary.companyRestrictions,
      },
    });
  }
  res.json({ admins });
});

module.exports = { listAdmins };
