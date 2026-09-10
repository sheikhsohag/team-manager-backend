'use strict';

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { queryOne, execute, transaction } = require('../config/db');
const { seedCompanyStatuses, applyIndividualBoundary } = require('./provision.service');

const ROUNDS = Number(process.env.BCRYPT_ROUNDS || 10);

function slugify(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 140) || 'workspace';
}

function hashPassword(plain) {
  return bcrypt.hash(plain, ROUNDS);
}

function signToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, isSuperAdmin: !!user.is_super_admin, companyId: user.company_id },
    process.env.JWT_SECRET || 'insecure-dev-secret',
    { expiresIn: process.env.JWT_EXPIRES_IN || '12h' }
  );
}

function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET || 'insecure-dev-secret');
}

async function login(email, password) {
  const user = await queryOne(
    `SELECT u.*, c.type AS company_type, c.name AS company_name
       FROM users u
       LEFT JOIN companies c ON c.id = u.company_id
      WHERE u.email = :email AND u.deleted_at IS NULL`,
    { email: String(email || '').toLowerCase() }
  );
  if (!user) throw Object.assign(new Error('Invalid credentials'), { status: 401 });
  if (user.status === 'suspended') throw Object.assign(new Error('Account suspended'), { status: 403 });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) throw Object.assign(new Error('Invalid credentials'), { status: 401 });

  await execute('UPDATE users SET last_login_at = NOW() WHERE id = :id', { id: user.id });

  const token = signToken(user);
  return { token, user: publicUser(user) };
}

function publicUser(u) {
  return {
    id: u.id, name: u.name, email: u.email, company_id: u.company_id,
    status: u.status, is_super_admin: !!u.is_super_admin,
    company_type: u.company_type || null,
    company_name: u.company_name || null,
  };
}

/**
 * Self-registration. Creates a brand-new company workspace and makes the
 * signer-up its Company Admin (full company powers, no super-admin/system perms).
 *
 *   accountType 'company'    -> workspace named `companyName`
 *   accountType 'individual' -> personal workspace named after the person
 *
 * Everything (company, user, role assignment, default statuses) runs in one
 * transaction so a partial signup can never leave orphaned rows.
 */
async function register({ name, email, password, accountType = 'company', companyName = null }) {
  const cleanEmail = String(email || '').toLowerCase().trim();
  const cleanName = String(name || '').trim();
  if (!cleanName || !cleanEmail || !password) {
    throw Object.assign(new Error('name, email and password are required'), { status: 400 });
  }
  if (String(password).length < 8) {
    throw Object.assign(new Error('Password must be at least 8 characters'), { status: 400 });
  }
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(cleanEmail)) {
    throw Object.assign(new Error('Invalid email address'), { status: 400 });
  }

  const existing = await queryOne('SELECT id FROM users WHERE email = :e', { e: cleanEmail });
  if (existing) throw Object.assign(new Error('An account with this email already exists'), { status: 409 });

  const isIndividual = accountType === 'individual';
  const wsName = isIndividual
    ? `${cleanName}'s Workspace`
    : (String(companyName || '').trim() || `${cleanName}'s Company`);

  const hash = await bcrypt.hash(password, ROUNDS);

  const userId = await transaction(async (t) => {
    // unique slug
    let base = slugify(wsName);
    let slug = base;
    for (let i = 2; await t.queryOne('SELECT id FROM companies WHERE slug = :s', { s: slug }); i += 1) {
      slug = `${base}-${i}`;
    }

    const companyRes = await t.execute(
      `INSERT INTO companies (name, slug, type, status, self_manage_permissions)
       VALUES (:name, :slug, :type, 'active', :self)`,
      { name: wsName, slug, type: isIndividual ? 'individual' : 'company', self: isIndividual ? 0 : 1 }
    );
    const companyId = companyRes.insertId;

    const userRes = await t.execute(
      `INSERT INTO users (company_id, name, email, password_hash, status)
       VALUES (:c, :n, :e, :h, 'active')`,
      { c: companyId, n: cleanName, e: cleanEmail, h: hash }
    );
    const newUserId = userRes.insertId;

    const role = await t.queryOne(
      "SELECT id FROM roles WHERE slug = 'company-admin' AND company_id IS NULL"
    );
    if (role) {
      await t.execute('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (:u, :r)', {
        u: newUserId, r: role.id,
      });
    }

    await seedCompanyStatuses(t.execute, companyId, newUserId);

    // Individual (solo) workspaces get the team/user/admin ceiling applied.
    if (isIndividual) {
      await applyIndividualBoundary(t.execute, t.query, companyId);
    }
    return newUserId;
  });

  const user = await queryOne(
    `SELECT u.*, c.type AS company_type, c.name AS company_name
       FROM users u
       LEFT JOIN companies c ON c.id = u.company_id
      WHERE u.id = :id`,
    { id: userId }
  );
  const token = signToken(user);
  return { token, user: publicUser(user) };
}

module.exports = { hashPassword, signToken, verifyToken, login, register, publicUser };
