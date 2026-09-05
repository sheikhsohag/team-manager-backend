'use strict';

const audit = require('../services/audit.service');
const { asyncHandler } = require('../middleware/error');

// GET /super-admin/audit-logs?companyId=&targetUserId=&action=&limit=&offset=
const list = asyncHandler(async (req, res) => {
  const filter = {
    action: req.query.action,
    targetUserId: req.query.targetUserId,
    limit: Math.min(Number(req.query.limit || 100), 500),
    offset: Number(req.query.offset || 0),
  };
  // Company admins may only see their own company's logs.
  if (req.user.is_super_admin) {
    if (req.query.companyId) filter.companyId = req.query.companyId;
  } else {
    filter.companyId = req.user.company_id;
  }
  const logs = await audit.list(filter);
  res.json({ logs });
});

module.exports = { list };
