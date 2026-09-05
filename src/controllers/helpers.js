'use strict';

const { queryOne } = require('../config/db');

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || null;
}

async function getUserOr404(userId) {
  const u = await queryOne(
    `SELECT id, company_id, name, email, status, is_super_admin, deleted_at
       FROM users WHERE id = :id`, { id: userId }
  );
  if (!u) throw Object.assign(new Error('User not found'), { status: 404 });
  return u;
}

/**
 * Company boundary check. A non-super-admin actor may only manage users inside
 * their own company, and may never modify a Super Admin. (Section 19 & 20.)
 */
function assertCanManageUser(actor, targetUser) {
  if (targetUser.is_super_admin && !actor.is_super_admin) {
    throw Object.assign(new Error('Cannot modify a Super Admin'), { status: 403 });
  }
  if (actor.is_super_admin) return;
  if (Number(targetUser.company_id) !== Number(actor.company_id)) {
    throw Object.assign(new Error('Cross-company access denied'), { status: 403 });
  }
}

function parseList(v) {
  if (Array.isArray(v)) return v;
  if (typeof v === 'string' && v.trim()) return v.split(',').map((s) => s.trim());
  return [];
}

module.exports = { clientIp, getUserOr404, assertCanManageUser, parseList };
