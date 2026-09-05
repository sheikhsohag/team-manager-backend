'use strict';

/**
 * Backend permission enforcement. THIS is the real gate — the frontend only
 * hides UI. Any unauthorized request is rejected with HTTP 403.
 *
 * Usage:
 *   router.delete('/tasks/:id', authenticate, can('task.delete'), handler)
 *   router.get('/x', authenticate, canAny(['report.view','report.generate']), handler)
 */

const permissionService = require('../services/permission.service');

function can(permissionKey) {
  return async function (req, res, next) {
    try {
      if (!req.user) return res.status(401).json({ error: 'Authentication required' });
      const allowed = await permissionService.can(req.user.id, permissionKey);
      if (!allowed) {
        return res.status(403).json({
          error: 'Forbidden',
          message: `Missing required permission: ${permissionKey}`,
          permission: permissionKey,
        });
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

function canAny(permissionKeys) {
  return async function (req, res, next) {
    try {
      if (!req.user) return res.status(401).json({ error: 'Authentication required' });
      const allowed = await permissionService.canAny(req.user.id, permissionKeys);
      if (!allowed) {
        return res.status(403).json({
          error: 'Forbidden',
          message: `Requires one of: ${permissionKeys.join(', ')}`,
          permissions: permissionKeys,
        });
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Enforce the company boundary for company-scoped admins: a non-super-admin can
 * only act on resources within their own company. Pass a function that extracts
 * the target company id from the request.
 */
function sameCompany(getTargetCompanyId) {
  return async function (req, res, next) {
    try {
      if (!req.user) return res.status(401).json({ error: 'Authentication required' });
      if (req.user.is_super_admin) return next(); // super admin crosses companies
      const targetCompanyId = await getTargetCompanyId(req);
      if (targetCompanyId == null) return res.status(404).json({ error: 'Resource not found' });
      if (Number(targetCompanyId) !== Number(req.user.company_id)) {
        return res.status(403).json({ error: 'Forbidden', message: 'Cross-company access denied' });
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = { can, canAny, sameCompany };
