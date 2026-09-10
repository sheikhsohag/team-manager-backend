'use strict';

const { verifyToken } = require('../services/auth.service');
const { queryOne } = require('../config/db');
const { AUTH_COOKIE } = require('./cookieAuth');

/** Read the raw auth token: prefer the httpOnly cookie, fall back to a Bearer header. */
function readToken(req) {
  // 1. httpOnly cookie — set by login, invisible to JavaScript (resists XSS/console theft).
  const cookieHeader = req.headers.cookie || '';
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    if (name === AUTH_COOKIE) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  // 2. Authorization: Bearer <token> — for curl / non-browser API clients.
  const header = req.headers.authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7) : null;
}

/**
 * Authenticates the request from the auth cookie (or a Bearer header) and
 * attaches the fresh user record to `req.user`.
 */
async function authenticate(req, res, next) {
  try {
    const token = readToken(req);
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
