'use strict';

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { queryOne, execute } = require('../config/db');

const ROUNDS = Number(process.env.BCRYPT_ROUNDS || 10);

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
    'SELECT * FROM users WHERE email = :email AND deleted_at IS NULL',
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
  };
}

module.exports = { hashPassword, signToken, verifyToken, login, publicUser };
