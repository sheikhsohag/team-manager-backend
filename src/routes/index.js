'use strict';

const express = require('express');
const { authenticate, requireSuperAdmin } = require('../middleware/auth');
const { can, canAny } = require('../middleware/authorize');

const auth = require('../controllers/auth.controller');
const permission = require('../controllers/permission.controller');
const user = require('../controllers/user.controller');
const admin = require('../controllers/admin.controller');
const company = require('../controllers/company.controller');
const role = require('../controllers/role.controller');
const template = require('../controllers/template.controller');
const audit = require('../controllers/audit.controller');
const task = require('../controllers/task.controller');
const team = require('../controllers/team.controller');
const status = require('../controllers/status.controller');
const report = require('../controllers/report.controller');
const permissionService = require('../services/permission.service');
const { asyncHandler } = require('../middleware/error');
const { upload } = require('../middleware/upload');

const router = express.Router();

// convenience guards
const MANAGE_PERMS = 'admin.permissions';
const VIEW_ADMINS = 'admin.view';

// ---------------------------------------------------------------- Auth ------
router.post('/auth/login', auth.login);
router.post('/auth/register', auth.register);
router.post('/auth/logout', auth.logout);
router.get('/auth/me', authenticate, auth.me);

// -------------------------------------------------------------- Self (me) ---
// Any authenticated user can view their own effective permissions.
router.get('/me/permissions', authenticate, asyncHandler(async (req, res) => {
  res.json(await permissionService.effectiveForUi(req.user.id));
}));

// The teams the current user belongs to (any authenticated user).
router.get('/me/teams', authenticate, team.myTeams);

// --------------------------------------------------------- Permissions ------
// Catalog is metadata; any authenticated user may read it to render matrices.
router.get('/permissions', authenticate, permission.catalog);
router.post('/permissions/simulate', authenticate, can(MANAGE_PERMS), permission.simulate);
router.post('/permissions/copy', authenticate, can(MANAGE_PERMS), permission.copy);
router.post('/permissions/bulk', authenticate, can(MANAGE_PERMS), permission.bulk);

// -------------------------------------------------------------- Users -------
router.get('/users', authenticate, can('user.view'), user.list);
router.post('/users', authenticate, can('user.create'), user.create);
router.get('/users/:id', authenticate, can('user.view'), user.getOne);
router.put('/users/:id', authenticate, can('user.update'), user.update);
router.post('/users/:id/suspend', authenticate, can('user.suspend'), user.suspend);
router.post('/users/:id/activate', authenticate, can('user.restore'), user.activate);
router.delete('/users/:id', authenticate, can('user.delete'), user.remove);
router.post('/users/:id/reset-password', authenticate, can('user.reset_password'), user.resetPassword);

// Per-user permission management
router.get('/users/:id/effective-permissions', authenticate, canAny([MANAGE_PERMS, VIEW_ADMINS, 'user.view']), user.effectivePermissions);
router.put('/users/:id/permissions', authenticate, can(MANAGE_PERMS), user.setPermissions);
router.post('/users/:id/permissions/reset', authenticate, can(MANAGE_PERMS), user.resetToRole);
router.post('/users/:id/permissions/apply-template', authenticate, can(MANAGE_PERMS), user.applyTemplate);

// -------------------------------------------------------------- Admins ------
router.get('/admins', authenticate, can(VIEW_ADMINS), admin.listAdmins);
// alias used by the super-admin UI
router.get('/super-admin/admins', authenticate, can(VIEW_ADMINS), admin.listAdmins);

// -------------------------------------------------------------- Roles -------
router.get('/roles', authenticate, canAny([VIEW_ADMINS, 'user.view', MANAGE_PERMS]), role.list);
router.get('/roles/:id', authenticate, canAny([VIEW_ADMINS, 'user.view', MANAGE_PERMS]), role.getOne);
router.post('/roles', authenticate, canAny(['system.roles', MANAGE_PERMS]), role.create);
router.put('/roles/:id', authenticate, canAny(['system.roles', MANAGE_PERMS]), role.update);
router.put('/roles/:id/permissions', authenticate, canAny(['system.roles', MANAGE_PERMS]), role.setPermissions);
router.delete('/roles/:id', authenticate, canAny(['system.roles', MANAGE_PERMS]), role.remove);

// ----------------------------------------------------------- Templates ------
router.get('/permission-templates', authenticate, canAny([MANAGE_PERMS, VIEW_ADMINS]), template.list);
router.get('/permission-templates/:id', authenticate, canAny([MANAGE_PERMS, VIEW_ADMINS]), template.getOne);
router.post('/permission-templates', authenticate, can(MANAGE_PERMS), template.create);
router.delete('/permission-templates/:id', authenticate, can(MANAGE_PERMS), template.remove);

// ----------------------------------------------- Companies (Super Admin) ----
router.get('/super-admin/companies', authenticate, requireSuperAdmin, company.list);
router.post('/super-admin/companies', authenticate, requireSuperAdmin, company.create);
router.put('/super-admin/companies/:id', authenticate, requireSuperAdmin, company.update);
router.post('/super-admin/companies/:id/activate', authenticate, requireSuperAdmin, company.setActive);
router.delete('/super-admin/companies/:id', authenticate, requireSuperAdmin, company.remove);
router.post('/super-admin/companies/:id/restore', authenticate, requireSuperAdmin, company.restore);
router.get('/super-admin/companies/:id/permissions', authenticate, requireSuperAdmin, company.getBoundary);
router.put('/super-admin/companies/:id/permissions', authenticate, requireSuperAdmin, company.setBoundary);

// Company self-service boundary (company admin, if enabled by Super Admin)
router.get('/admin/company/permissions', authenticate, can('company.permissions'), company.getOwnBoundary);
router.put('/admin/company/permissions', authenticate, can('company.permissions'), company.setOwnBoundary);

// ----------------------------------------------------------- Audit logs -----
router.get('/super-admin/audit-logs', authenticate, can('audit.view'), audit.list);
router.get('/audit-logs', authenticate, can('audit.view'), audit.list);

// ------------------------------------------------------- Task statuses ------
// Any authenticated user may read the status list (to render pickers/filters).
router.get('/statuses', authenticate, status.list);
router.post('/statuses', authenticate, can('task.status_manage'), status.create);
router.put('/statuses/:id', authenticate, can('task.status_manage'), status.update);
router.delete('/statuses/:id', authenticate, can('task.status_manage'), status.remove);

// --------------------------------------------------------------- Tasks ------
router.get('/tasks', authenticate, can('task.view'), task.list);
router.post('/tasks', authenticate, can('task.create'), task.create);
router.get('/tasks/:id', authenticate, can('task.view'), task.getOne);
router.put('/tasks/:id', authenticate, can('task.update'), task.update);
router.post('/tasks/:id/status', authenticate, can('task.change_status'), task.changeStatus);
router.delete('/tasks/:id', authenticate, can('task.delete'), task.remove);

// Task comments
router.get('/tasks/:id/comments', authenticate, can('task.view'), task.listComments);
router.post('/tasks/:id/comments', authenticate, can('task.comment'), task.addComment);

// Task attachments (multipart field name: "file")
router.get('/tasks/:id/attachments', authenticate, can('task.view'), task.listAttachments);
router.post('/tasks/:id/attachments', authenticate, can('task.attach_file'), upload.single('file'), task.uploadAttachment);
router.get('/attachments/:attId/download', authenticate, can('task.view'), task.downloadAttachment);
router.delete('/attachments/:attId', authenticate, can('task.attach_file'), task.removeAttachment);

// Per-task sharing
router.post('/tasks/:id/share', authenticate, can('task.share'), task.shareTask);
router.delete('/tasks/:id/share/:userId', authenticate, can('task.share'), task.unshareTask);

// Company roster for pickers (assignee / filters) — broader than user.view.
router.get('/company/users', authenticate,
  canAny(['user.view', 'task.create', 'task.assign', 'task.view_all', 'team.grant_member_perms']),
  team.companyUsers);

// --------------------------------------------------------------- Teams ------
router.get('/teams', authenticate, can('team.view'), team.list);
router.post('/teams', authenticate, can('team.create'), team.create);
router.delete('/teams/:id', authenticate, can('team.delete'), team.remove);
router.get('/teams/:id/members', authenticate, can('team.view'), team.members);
router.post('/teams/:id/members', authenticate, can('team.add_member'), team.addMember);
router.put('/teams/:id/members/:userId/role', authenticate, can('team.manage_leads'), team.setMemberRole);
router.delete('/teams/:id/members/:userId', authenticate, can('team.remove_member'), team.removeMember);

// Lead-grants-member access (task permissions)
router.get('/teams/:id/members/:userId/access', authenticate, canAny(['team.grant_member_perms', MANAGE_PERMS]), team.memberAccess);
router.put('/teams/:id/members/:userId/access', authenticate, can('team.grant_member_perms'), team.setMemberAccess);

// Task-list access ("let X see Y's tasks")
router.get('/task-access', authenticate, canAny(['team.grant_member_perms', 'task.view_all', MANAGE_PERMS]), team.listAccess);
router.post('/task-access', authenticate, can('team.grant_member_perms'), team.grantAccess);
router.delete('/task-access/:ownerId/:viewerId', authenticate, can('team.grant_member_perms'), team.revokeAccess);

// -------------------------------------------------------------- Reports -----
router.get('/reports', authenticate, can('report.view'), report.summary);
router.post('/reports/generate', authenticate, can('report.generate'), report.generate);
router.get('/reports/export', authenticate, can('report.export'), report.exportCsv);

module.exports = router;
