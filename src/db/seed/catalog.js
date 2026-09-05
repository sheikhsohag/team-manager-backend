'use strict';

/**
 * The canonical catalog of permission groups, permissions, default roles and
 * templates. Editing this file + re-running the seeder is how you add new
 * permissions later — no authorization code changes required.
 *
 * `action` labels drive the permission matrix columns in the UI.
 */

// ---- Permission groups (modules) -----------------------------------------
const GROUPS = [
  { key: 'company', label: 'Company Management', sort_order: 10 },
  { key: 'user', label: 'User Management', sort_order: 20 },
  { key: 'team', label: 'Team Management', sort_order: 30 },
  { key: 'project', label: 'Project Management', sort_order: 40 },
  { key: 'task', label: 'Task Management', sort_order: 50 },
  { key: 'requirement', label: 'Requirements', sort_order: 60 },
  { key: 'report', label: 'Reports', sort_order: 70 },
  { key: 'credential', label: 'Credentials', sort_order: 80 },
  { key: 'admin', label: 'Admin Management', sort_order: 90 },
  { key: 'audit', label: 'Audit Logs', sort_order: 100 },
  { key: 'system', label: 'System', sort_order: 110 },
];

// ---- Permissions ----------------------------------------------------------
// [key, action, label, description?, isSystem?]
const PERMISSIONS = {
  company: [
    ['company.view', 'view', 'View Companies'],
    ['company.create', 'create', 'Create Companies'],
    ['company.update', 'update', 'Update Companies'],
    ['company.delete', 'delete', 'Delete Companies'],
    ['company.restore', 'restore', 'Restore Companies'],
    ['company.activate', 'activate', 'Activate / Deactivate Companies'],
    ['company.permissions', 'permissions', 'Configure Company Permissions'],
  ],
  user: [
    ['user.view', 'view', 'View Users'],
    ['user.create', 'create', 'Create Users'],
    ['user.update', 'update', 'Update Users'],
    ['user.delete', 'delete', 'Delete Users'],
    ['user.suspend', 'suspend', 'Suspend Users'],
    ['user.restore', 'restore', 'Restore / Activate Users'],
    ['user.reset_password', 'reset_password', 'Reset User Passwords'],
  ],
  team: [
    ['team.view', 'view', 'View Teams'],
    ['team.create', 'create', 'Create Teams'],
    ['team.update', 'update', 'Update Teams'],
    ['team.delete', 'delete', 'Delete Teams'],
    ['team.add_member', 'add_member', 'Add Members'],
    ['team.remove_member', 'remove_member', 'Remove Members'],
  ],
  project: [
    ['project.view', 'view', 'View Projects'],
    ['project.create', 'create', 'Create Projects'],
    ['project.update', 'update', 'Update Projects'],
    ['project.delete', 'delete', 'Delete Projects'],
  ],
  task: [
    ['task.view', 'view', 'View Tasks'],
    ['task.create', 'create', 'Create Tasks'],
    ['task.update', 'update', 'Update Tasks'],
    ['task.delete', 'delete', 'Delete Tasks'],
    ['task.assign', 'assign', 'Assign Tasks'],
    ['task.reassign', 'reassign', 'Reassign Tasks'],
    ['task.change_status', 'change_status', 'Change Task Status'],
    ['task.change_priority', 'change_priority', 'Change Task Priority'],
    ['task.complete', 'complete', 'Complete Tasks'],
    ['task.reopen', 'reopen', 'Reopen Tasks'],
    ['task.comment', 'comment', 'Comment on Tasks'],
    ['task.add_note', 'add_note', 'Add Notes'],
    ['task.share', 'share', 'Share Tasks'],
    ['task.attach_file', 'attach_file', 'Attach Files'],
    ['task.track_time', 'track_time', 'Track Time'],
  ],
  requirement: [
    ['requirement.create', 'create', 'Create Requirements'],
    ['requirement.view', 'view', 'View Requirements'],
    ['requirement.update', 'update', 'Update Requirements'],
    ['requirement.respond', 'respond', 'Respond to Requirements'],
    ['requirement.close', 'close', 'Close Requirements'],
  ],
  report: [
    ['report.view', 'view', 'View Reports'],
    ['report.generate', 'generate', 'Generate Reports'],
    ['report.export', 'export', 'Export Reports'],
    ['report.delete', 'delete', 'Delete Reports'],
  ],
  credential: [
    ['credential.view', 'view', 'View Credentials'],
    ['credential.create', 'create', 'Create Credentials'],
    ['credential.update', 'update', 'Update Credentials'],
    ['credential.delete', 'delete', 'Delete Credentials'],
    ['credential.share', 'share', 'Share Credentials'],
  ],
  admin: [
    ['admin.view', 'view', 'View Admins'],
    ['admin.create', 'create', 'Create Admins'],
    ['admin.update', 'update', 'Update Admins'],
    ['admin.delete', 'delete', 'Delete Admins'],
    ['admin.permissions', 'permissions', 'Manage Admin Permissions'],
  ],
  audit: [
    ['audit.view', 'view', 'View Audit Logs'],
    ['audit.export', 'export', 'Export Audit Logs'],
  ],
  system: [
    ['system.roles', 'roles', 'Manage System Roles', 'System-wide role management', true],
    ['system.permissions', 'permissions', 'Manage System Permissions', 'System-wide permission management', true],
    ['system.settings', 'settings', 'Configure System Settings', null, true],
    ['system.analytics', 'analytics', 'View System Analytics', null, true],
  ],
};

// Flatten into rows the seeder can insert.
function flatPermissions() {
  const rows = [];
  for (const [groupKey, list] of Object.entries(PERMISSIONS)) {
    for (const [key, action, label, description = null, isSystem = false] of list) {
      rows.push({ key, groupKey, action, label, description, isSystem });
    }
  }
  return rows;
}

const ALL_PERMISSION_KEYS = flatPermissions().map((p) => p.key);

// ---- Default roles --------------------------------------------------------
// Super Admin is handled specially (gets ALL permissions).
const ROLES = [
  {
    name: 'Company Admin', slug: 'company-admin', level: 'company', is_system: true,
    description: 'Administers a single company. Capabilities are defined by permissions, not the role name.',
    permissions: [
      'company.view', 'company.update', 'company.permissions',
      'user.view', 'user.create', 'user.update', 'user.suspend', 'user.restore', 'user.reset_password',
      'team.view', 'team.create', 'team.update', 'team.delete', 'team.add_member', 'team.remove_member',
      'project.view', 'project.create', 'project.update', 'project.delete',
      'task.view', 'task.create', 'task.update', 'task.assign', 'task.reassign',
      'task.change_status', 'task.change_priority', 'task.complete', 'task.reopen', 'task.comment', 'task.add_note',
      'report.view', 'report.generate', 'report.export',
      'admin.view', 'admin.create', 'admin.update', 'admin.permissions',
      'audit.view',
      'requirement.create', 'requirement.view', 'requirement.update', 'requirement.respond', 'requirement.close',
    ],
  },
  {
    name: 'Company Manager', slug: 'company-manager', level: 'company', is_system: true,
    description: 'Manages day-to-day work but cannot administer admins or company settings.',
    permissions: [
      'company.view',
      'user.view', 'user.create', 'user.update',
      'team.view', 'team.create', 'team.update', 'team.add_member', 'team.remove_member',
      'project.view', 'project.create', 'project.update',
      'task.view', 'task.create', 'task.update', 'task.assign', 'task.reassign',
      'task.change_status', 'task.change_priority', 'task.complete', 'task.reopen', 'task.comment', 'task.add_note',
      'report.view', 'report.generate',
      'requirement.create', 'requirement.view', 'requirement.update', 'requirement.respond',
    ],
  },
  {
    name: 'Company Viewer', slug: 'company-viewer', level: 'company', is_system: true,
    description: 'Read-only visibility across the company.',
    permissions: [
      'company.view', 'user.view', 'team.view', 'project.view', 'task.view',
      'report.view', 'requirement.view',
    ],
  },
  {
    name: 'Team Lead', slug: 'team-lead', level: 'team', is_system: true,
    description: 'Leads a team. Explicitly scoped — receives nothing beyond assigned permissions.',
    permissions: [
      'team.view',
      'task.view', 'task.create', 'task.update', 'task.assign',
      'task.change_status', 'task.comment', 'task.add_note',
      'report.view',
    ],
  },
  {
    name: 'Team Manager', slug: 'team-manager', level: 'team', is_system: true,
    description: 'Manages a team and its members.',
    permissions: [
      'team.view', 'team.add_member', 'team.remove_member',
      'task.view', 'task.create', 'task.update', 'task.assign', 'task.reassign',
      'task.change_status', 'task.change_priority', 'task.complete', 'task.comment', 'task.add_note',
      'report.view', 'report.generate',
    ],
  },
  {
    name: 'Team Member', slug: 'team-member', level: 'team', is_system: true,
    description: 'Works on tasks assigned to them.',
    permissions: [
      'team.view',
      'task.view', 'task.update', 'task.change_status', 'task.complete',
      'task.comment', 'task.add_note', 'task.attach_file', 'task.track_time',
    ],
  },
  // Example custom roles from the spec
  {
    name: 'Senior Team Lead', slug: 'senior-team-lead', level: 'team', is_system: false,
    description: 'Custom role — extended Team Lead capabilities.',
    permissions: [
      'task.view', 'task.create', 'task.update', 'task.assign', 'task.reassign', 'task.delete',
      'task.complete', 'report.view', 'report.generate', 'report.export',
    ],
  },
  {
    name: 'Junior Team Lead', slug: 'junior-team-lead', level: 'team', is_system: false,
    description: 'Custom role — reduced Team Lead capabilities.',
    permissions: [
      'task.view', 'task.create', 'task.update', 'task.assign', 'task.change_status', 'report.view',
    ],
  },
];

// ---- Permission templates -------------------------------------------------
const TEMPLATES = [
  {
    name: 'Full Admin', slug: 'full-admin', description: 'Everything a company admin can do.',
    permissions: ROLES.find((r) => r.slug === 'company-admin').permissions,
  },
  {
    name: 'Project Manager', slug: 'project-manager', description: 'Runs projects and teams.',
    permissions: [
      'project.view', 'project.create', 'project.update', 'project.delete',
      'team.view', 'team.create', 'team.update', 'team.add_member', 'team.remove_member',
      'task.view', 'task.create', 'task.update', 'task.assign', 'task.reassign',
      'task.change_status', 'task.change_priority', 'task.complete',
      'report.view', 'report.generate', 'report.export',
    ],
  },
  {
    name: 'Developer', slug: 'developer', description: 'Works on tasks.',
    permissions: [
      'task.view', 'task.update', 'task.change_status', 'task.complete', 'task.reopen',
      'task.comment', 'task.add_note', 'task.attach_file', 'task.track_time', 'project.view',
    ],
  },
  {
    name: 'QA', slug: 'qa', description: 'Quality assurance.',
    permissions: [
      'task.view', 'task.update', 'task.change_status', 'task.reopen',
      'task.comment', 'task.add_note', 'report.view', 'project.view',
    ],
  },  
  {
    name: 'Support', slug: 'support', description: 'Support & requirements handling.',
    permissions: [
      'task.view', 'task.comment', 'requirement.view', 'requirement.respond',
      'requirement.create', 'report.view',
    ],
  },
  {
    name: 'Viewer', slug: 'viewer', description: 'Read-only.',
    permissions: ['company.view', 'user.view', 'team.view', 'project.view', 'task.view', 'report.view'],
  },
];

module.exports = {
  GROUPS,
  PERMISSIONS,
  ROLES,
  TEMPLATES,
  flatPermissions,
  ALL_PERMISSION_KEYS,
};
