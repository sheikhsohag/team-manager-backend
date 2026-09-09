'use strict';

/**
 * DatabaseSeeder — orchestrates all seeders. Idempotent: safe to run repeatedly.
 *
 *   1. permission_groups + permissions          (from catalog.js)
 *   2. system roles + role_permissions          (from catalog.js)
 *   3. permission templates                      (from catalog.js)
 *   4. Super Admin (SuperAdminSeeder)            (from env, never duplicated)
 *   5. optional demo companies / admins / users  (SEED_DEMO_DATA=true)
 */

require('dotenv').config();
const bcrypt = require('bcryptjs');
const { pool, query, queryOne, execute } = require('../../config/db');
const catalog = require('./catalog');
const { seedCompanyStatuses } = require('../../services/provision.service');

const ROUNDS = Number(process.env.BCRYPT_ROUNDS || 10);

async function upsertGroups() {
  for (const g of catalog.GROUPS) {
    await execute(
      `INSERT INTO permission_groups (\`key\`, label, sort_order)
       VALUES (:key, :label, :sort)
       ON DUPLICATE KEY UPDATE label = VALUES(label), sort_order = VALUES(sort_order)`,
      { key: g.key, label: g.label, sort: g.sort_order }
    );
  }
  const rows = await query('SELECT id, `key` FROM permission_groups');
  return new Map(rows.map((r) => [r.key, r.id]));
}

async function upsertPermissions(groupIdByKey) {
  for (const p of catalog.flatPermissions()) {
    const groupId = groupIdByKey.get(p.groupKey);
    await execute(
      `INSERT INTO permissions (\`key\`, group_id, action, label, description, is_system)
       VALUES (:key, :group_id, :action, :label, :description, :is_system)
       ON DUPLICATE KEY UPDATE
         group_id = VALUES(group_id), action = VALUES(action),
         label = VALUES(label), description = VALUES(description), is_system = VALUES(is_system)`,
      {
        key: p.key, group_id: groupId, action: p.action, label: p.label,
        description: p.description, is_system: p.isSystem ? 1 : 0,
      }
    );
  }
  const rows = await query('SELECT id, `key` FROM permissions');
  return new Map(rows.map((r) => [r.key, r.id]));
}

async function upsertSystemRoles(permIdByKey) {
  for (const r of catalog.ROLES) {
    // NOTE: MySQL unique indexes treat NULL as distinct, so a plain
    // INSERT ... ON DUPLICATE KEY on (company_id=NULL, slug) never matches.
    // We must SELECT-then-INSERT/UPDATE to stay idempotent for system rows.
    let role = await queryOne(
      'SELECT id FROM roles WHERE slug = :slug AND company_id IS NULL', { slug: r.slug }
    );
    if (role) {
      await execute(
        `UPDATE roles SET name = :name, level = :level, is_system = :is_system, description = :description
          WHERE id = :id`,
        { id: role.id, name: r.name, level: r.level, is_system: r.is_system ? 1 : 0, description: r.description }
      );
    } else {
      const res = await execute(
        `INSERT INTO roles (company_id, name, slug, level, is_system, description)
         VALUES (NULL, :name, :slug, :level, :is_system, :description)`,
        { name: r.name, slug: r.slug, level: r.level, is_system: r.is_system ? 1 : 0, description: r.description }
      );
      role = { id: res.insertId };
    }
    // reset the role's permissions to match the catalog
    await execute('DELETE FROM role_permissions WHERE role_id = :id', { id: role.id });
    for (const key of r.permissions) {
      const pid = permIdByKey.get(key);
      if (!pid) continue;
      await execute(
        'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (:r, :p)',
        { r: role.id, p: pid }
      );
    }
  }
  const rows = await query('SELECT id, slug FROM roles WHERE company_id IS NULL');
  return new Map(rows.map((r) => [r.slug, r.id]));
}

async function upsertTemplates(permIdByKey) {
  for (const t of catalog.TEMPLATES) {
    let tpl = await queryOne(
      'SELECT id FROM permission_templates WHERE slug = :slug AND company_id IS NULL', { slug: t.slug }
    );
    if (tpl) {
      await execute(
        'UPDATE permission_templates SET name = :name, description = :description, is_system = 1 WHERE id = :id',
        { id: tpl.id, name: t.name, description: t.description }
      );
    } else {
      const res = await execute(
        `INSERT INTO permission_templates (company_id, name, slug, description, is_system)
         VALUES (NULL, :name, :slug, :description, 1)`,
        { name: t.name, slug: t.slug, description: t.description }
      );
      tpl = { id: res.insertId };
    }
    await execute('DELETE FROM permission_template_items WHERE template_id = :id', { id: tpl.id });
    for (const key of t.permissions) {
      const pid = permIdByKey.get(key);
      if (!pid) continue;
      await execute(
        'INSERT IGNORE INTO permission_template_items (template_id, permission_id) VALUES (:t, :p)',
        { t: tpl.id, p: pid }
      );
    }
  }
}

/**
 * SuperAdminSeeder — creates the initial super admin from env vars.
 * Never creates duplicates; assigns the Super Admin (system) capability.
 */
async function seedSuperAdmin() {
  const name = process.env.SUPER_ADMIN_NAME || 'Super Admin';
  const email = (process.env.SUPER_ADMIN_EMAIL || 'superadmin@example.com').toLowerCase();
  const password = process.env.SUPER_ADMIN_PASSWORD || 'ChangeMe@123';

  const existing = await queryOne('SELECT id FROM users WHERE email = :email', { email });
  if (existing) {
    // ensure the flag is set, but do NOT reset the password of an existing account
    await execute('UPDATE users SET is_super_admin = 1, status = "active", deleted_at = NULL WHERE id = :id', {
      id: existing.id,
    });
    console.log(`Super Admin already exists (${email}) — left credentials untouched.`);
    return existing.id;
  }

  const hash = await bcrypt.hash(password, ROUNDS);
  const res = await execute(
    `INSERT INTO users (company_id, name, email, password_hash, status, is_super_admin)
     VALUES (NULL, :name, :email, :hash, 'active', 1)`,
    { name, email, hash }
  );
  console.log(`Created Super Admin: ${email}`);
  // Super Admin authorization is by the is_super_admin flag (always-allow), so
  // it does not need explicit role/permission rows — but for auditability we do
  // NOT assign per-permission rows; the engine short-circuits for super admins.
  return res.insertId;
}

async function seedDemoData(roleIdBySlug, permIdByKey) {
  if (String(process.env.SEED_DEMO_DATA).toLowerCase() !== 'true') return;

  const existing = await queryOne('SELECT id FROM companies LIMIT 1');
  if (existing) {
    console.log('Demo data already present — skipping.');
    return;
  }

  const hash = await bcrypt.hash('Password@123', ROUNDS);

  async function createCompany(name, slug, selfManage = 1) {
    const res = await execute(
      `INSERT INTO companies (name, slug, status, self_manage_permissions)
       VALUES (:name, :slug, 'active', :self)`,
      { name, slug, self: selfManage }
    );
    return res.insertId;
  }

  async function createUser(companyId, name, email, roleSlug) {
    const res = await execute(
      `INSERT INTO users (company_id, name, email, password_hash, status)
       VALUES (:company_id, :name, :email, :hash, 'active')`,
      { company_id: companyId, name, email: email.toLowerCase(), hash }
    );
    const roleId = roleIdBySlug.get(roleSlug);
    if (roleId) {
      await execute('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (:u, :r)', {
        u: res.insertId, r: roleId,
      });
    }
    return res.insertId;
  }

  const companyA = await createCompany('Acme Corp', 'acme');
  const companyB = await createCompany('Globex Inc', 'globex');

  // Dynamic statuses for each demo company
  await seedCompanyStatuses(execute, companyA);
  await seedCompanyStatuses(execute, companyB);

  // Admin A — extra powers via user ALLOW overrides
  const adminA = await createUser(companyA, 'Admin A', 'admina@acme.test', 'company-admin');
  // Admin B — same role, fewer powers via user DENY overrides
  const adminB = await createUser(companyA, 'Admin B', 'adminb@acme.test', 'company-admin');
  const adminC = await createUser(companyB, 'Admin C', 'adminc@globex.test', 'company-manager');

  const larry = await createUser(companyA, 'Lead Larry', 'larry@acme.test', 'team-lead');
  const mary = await createUser(companyA, 'Member Mary', 'mary@acme.test', 'team-member');
  const nate = await createUser(companyA, 'Member Nate', 'nate@acme.test', 'team-member');

  // Demonstrate user-specific overrides:
  // Admin A gets extra ALLOW: task.delete, report.export, user.delete, admin.create
  for (const key of ['task.delete', 'report.export', 'user.delete', 'admin.create']) {
    await execute(
      `INSERT INTO user_permissions (user_id, permission_id, effect) VALUES (:u, :p, 'allow')
       ON DUPLICATE KEY UPDATE effect = 'allow'`,
      { u: adminA, p: permIdByKey.get(key) }
    );
  }
  // Admin B gets a DENY on report.export and user.suspend (less than the role grants)
  for (const key of ['report.export', 'user.suspend']) {
    await execute(
      `INSERT INTO user_permissions (user_id, permission_id, effect) VALUES (:u, :p, 'deny')
       ON DUPLICATE KEY UPDATE effect = 'deny'`,
      { u: adminB, p: permIdByKey.get(key) }
    );
  }

  // Company B boundary: disable credential management + user deletion company-wide
  for (const key of ['credential.view', 'credential.create', 'user.delete']) {
    const pid = permIdByKey.get(key);
    if (pid) {
      await execute(
        `INSERT INTO company_permissions (company_id, permission_id, effect) VALUES (:c, :p, 'deny')
         ON DUPLICATE KEY UPDATE effect = 'deny'`,
        { c: companyB, p: pid }
      );
    }
  }

  // A little domain data so permissions guard real resources
  const teamRes = await execute('INSERT INTO teams (company_id, name) VALUES (:c, :n)', {
    c: companyA, n: 'Platform Team',
  });
  const teamId = teamRes.insertId;
  const projRes = await execute('INSERT INTO projects (company_id, team_id, name) VALUES (:c, :t, :n)', {
    c: companyA, t: teamId, n: 'Website Revamp',
  });

  // Seat Larry as lead, Mary & Nate as members of the Platform Team
  await execute("INSERT INTO team_members (team_id, user_id, role_in_team) VALUES (:t, :u, 'lead')", { t: teamId, u: larry });
  await execute("INSERT INTO team_members (team_id, user_id, role_in_team) VALUES (:t, :u, 'member')", { t: teamId, u: mary });
  await execute("INSERT INTO team_members (team_id, user_id, role_in_team) VALUES (:t, :u, 'member')", { t: teamId, u: nate });

  // Company A statuses (fetch a couple for demo tasks)
  const inProg = await queryOne("SELECT id FROM task_statuses WHERE company_id = :c AND name = 'In Progress'", { c: companyA });
  const todo = await queryOne("SELECT id FROM task_statuses WHERE company_id = :c AND name = 'To Do'", { c: companyA });

  const mainTask = await execute(
    `INSERT INTO tasks (company_id, team_id, project_id, title, heading, description, status_id, priority, assignee_id, created_by)
     VALUES (:c, :team, :p, 'Design landing page', 'Marketing site refresh', 'Create the new hero + pricing sections.', :st, 'high', :a, :cb)`,
    { c: companyA, team: teamId, p: projRes.insertId, st: inProg ? inProg.id : null, a: mary, cb: larry }
  );
  // A subtask under it
  await execute(
    `INSERT INTO tasks (company_id, team_id, parent_id, title, status_id, priority, assignee_id, created_by)
     VALUES (:c, :team, :parent, 'Export hero images', :st, 'medium', :a, :cb)`,
    { c: companyA, team: teamId, parent: mainTask.insertId, st: todo ? todo.id : null, a: mary, cb: larry }
  );
  // Give Mary an explicit task.create ALLOW (lead granted it) so she can create tasks
  const taskCreate = await queryOne("SELECT id FROM permissions WHERE `key` = 'task.create'");
  if (taskCreate) {
    await execute(
      `INSERT INTO user_permissions (user_id, permission_id, effect) VALUES (:u, :p, 'allow')
       ON DUPLICATE KEY UPDATE effect = 'allow'`,
      { u: mary, p: taskCreate.id }
    );
  }
  // Let Nate see Mary's task list ("show this list" demo)
  await execute(
    `INSERT INTO task_list_shares (company_id, owner_id, viewer_id, granted_by) VALUES (:c, :o, :v, :g)`,
    { c: companyA, o: mary, v: nate, g: larry }
  );

  console.log('Seeded demo data (Acme Corp, Globex Inc, Admin A/B/C, Larry/Mary/Nate, teams, statuses, tasks).');
  console.log('Demo login password for all demo users: Password@123');
}

async function main() {
  try {
    console.log('Seeding database...');
    const groupIdByKey = await upsertGroups();
    const permIdByKey = await upsertPermissions(groupIdByKey);
    const roleIdBySlug = await upsertSystemRoles(permIdByKey);
    await upsertTemplates(permIdByKey);
    await seedSuperAdmin();
    await seedDemoData(roleIdBySlug, permIdByKey);
    console.log('Seeding complete.');
  } catch (err) {
    console.error('Seeding failed:', err);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

if (require.main === module) main();

module.exports = { seedSuperAdmin };
