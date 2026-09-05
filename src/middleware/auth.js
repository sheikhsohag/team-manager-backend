'use strict';

const { verifyToken } = require('../services/auth.service');
const { queryOne } = require('../config/db');

/**
 * Authenticates the request from the `Authorization: Bearer <token>` header
 * and attaches the fresh user record to `req.user`.
 */
async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Authentication required' });

    let payload;
    try {
      payload = verifyToken(token);
    } catch {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const user = await queryOne(
      `SELECT id, company_id, name, email, status, is_super_admin
         FROM users WHERE id = :id AND deleted_at IS NULL`,
      { id: payload.sub }
    );
    if (!user) return res.status(401).json({ error: 'User no longer exists' });
    if (user.status === 'suspended') return res.status(403).json({ error: 'Account suspended' });

    req.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      company_id: user.company_id,
      status: user.status,
      is_super_admin: !!user.is_super_admin,
    };
    next();
  } catch (err) {
    next(err);
  }
}

/** Guard that requires the user to be a Super Admin. */
function requireSuperAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required' });
  if (!req.user.is_super_admin) return res.status(403).json({ error: 'Super Admin access required' });
  next();
}

module.exports = { authenticate, requireSuperAdmin };
