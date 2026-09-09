'use strict';

const authService = require('../services/auth.service');
const permissionService = require('../services/permission.service');
const { asyncHandler } = require('../middleware/error');

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
  const result = await authService.login(email, password);
  res.json(result);
});

// POST /auth/register  { name, email, password, accountType, companyName? }
const register = asyncHandler(async (req, res) => {
  const { name, email, password, accountType = 'company', companyName = null } = req.body || {};
  const result = await authService.register({ name, email, password, accountType, companyName });
  res.status(201).json(result);
});

// GET /auth/me — current user + their effective permission keys (for UI gating)
const me = asyncHandler(async (req, res) => {
  const eff = await permissionService.effectiveForUi(req.user.id);
  res.json({
    user: req.user,
    roles: eff.roles,
    allowedKeys: eff.allowedKeys,
    summary: eff.summary,
  });
});

module.exports = { login, register, me };
