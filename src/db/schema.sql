-- =====================================================================
--  Multi-Company Task Manager — schema
--  Permission model: role-based + user-specific overrides + company boundary
--  Engine: InnoDB (FK support), utf8mb4
-- =====================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- ---------------------------------------------------------------------
-- Companies
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companies (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name          VARCHAR(150) NOT NULL,
  slug          VARCHAR(160) NOT NULL,
  -- 'company' = full workspace (teams/members); 'individual' = solo workspace
  type          ENUM('company','individual') NOT NULL DEFAULT 'company',
  status        ENUM('active','inactive') NOT NULL DEFAULT 'active',
  -- true = the company is allowed to self-manage its own permission boundary
  self_manage_permissions TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at    DATETIME NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_companies_slug (slug),
  KEY idx_companies_status (status),
  KEY idx_companies_deleted (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Users (includes Super Admin, who has company_id = NULL + is_super_admin = 1)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  company_id     BIGINT UNSIGNED NULL,
  name           VARCHAR(150) NOT NULL,
  email          VARCHAR(190) NOT NULL,
  password_hash  VARCHAR(255) NOT NULL,
  status         ENUM('active','suspended') NOT NULL DEFAULT 'active',
  is_super_admin TINYINT(1) NOT NULL DEFAULT 0,
  last_login_at  DATETIME NULL,
  deleted_at     DATETIME NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email),
  KEY idx_users_company (company_id),
  KEY idx_users_status (status),
  KEY idx_users_deleted (deleted_at),
  CONSTRAINT fk_users_company FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Permission groups (modules): "User Management", "Task Management", ...
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permission_groups (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `key`       VARCHAR(60) NOT NULL,
  label       VARCHAR(120) NOT NULL,
  sort_order  INT NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE KEY uq_permission_groups_key (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Permissions (action-based): task.delete, report.export, ...
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permissions (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `key`        VARCHAR(100) NOT NULL,             -- e.g. task.delete
  group_id     BIGINT UNSIGNED NOT NULL,
  action       VARCHAR(60) NOT NULL,              -- e.g. delete
  label        VARCHAR(150) NOT NULL,             -- e.g. Delete Tasks
  description  VARCHAR(255) NULL,
  is_system    TINYINT(1) NOT NULL DEFAULT 0,     -- system-level (super-admin only) perms
  PRIMARY KEY (id),
  UNIQUE KEY uq_permissions_key (`key`),
  KEY idx_permissions_group (group_id),
  CONSTRAINT fk_permissions_group FOREIGN KEY (group_id) REFERENCES permission_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Roles. company_id NULL => system/global role. Otherwise a company custom role.
-- level: system | company | team
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  company_id  BIGINT UNSIGNED NULL,
  name        VARCHAR(120) NOT NULL,
  slug        VARCHAR(140) NOT NULL,
  level       ENUM('system','company','team') NOT NULL DEFAULT 'company',
  is_system   TINYINT(1) NOT NULL DEFAULT 0,      -- built-in role, not deletable
  description VARCHAR(255) NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  -- a slug is unique within a company scope (NULL company handled at app layer)
  UNIQUE KEY uq_roles_company_slug (company_id, slug),
  KEY idx_roles_level (level),
  CONSTRAINT fk_roles_company FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- role_permissions: which permissions a role grants
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id       BIGINT UNSIGNED NOT NULL,
  permission_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  KEY idx_rp_permission (permission_id),
  CONSTRAINT fk_rp_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
  CONSTRAINT fk_rp_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- user_roles: which roles a user has (a user may have several)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
  user_id BIGINT UNSIGNED NOT NULL,
  role_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (user_id, role_id),
  KEY idx_ur_role (role_id),
  CONSTRAINT fk_ur_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_ur_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- user_permissions: user-specific overrides (unifies "permission_overrides").
-- effect = 'allow' adds beyond the role; effect = 'deny' removes even if role allows.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_permissions (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id       BIGINT UNSIGNED NOT NULL,
  permission_id BIGINT UNSIGNED NOT NULL,
  effect        ENUM('allow','deny') NOT NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_user_permission (user_id, permission_id),
  KEY idx_up_permission (permission_id),
  CONSTRAINT fk_up_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_up_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- company_roles: which roles are enabled/available to a company
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS company_roles (
  company_id BIGINT UNSIGNED NOT NULL,
  role_id    BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (company_id, role_id),
  KEY idx_cr_role (role_id),
  CONSTRAINT fk_cr_company FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE,
  CONSTRAINT fk_cr_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- company_permissions: the company boundary / ceiling.
--   effect = 'deny'  => permission is DISABLED for the whole company (hard ceiling)
--   (absence of a deny row => permission is available to the company)
-- This is what prevents company admins from escalating beyond system policy.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS company_permissions (
  company_id    BIGINT UNSIGNED NOT NULL,
  permission_id BIGINT UNSIGNED NOT NULL,
  effect        ENUM('allow','deny') NOT NULL DEFAULT 'deny',
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (company_id, permission_id),
  KEY idx_cp_permission (permission_id),
  CONSTRAINT fk_cp_company FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE,
  CONSTRAINT fk_cp_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Permission templates (Full Admin, Project Manager, Developer, QA, ...)
-- company_id NULL => global template.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permission_templates (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  company_id  BIGINT UNSIGNED NULL,
  name        VARCHAR(120) NOT NULL,
  slug        VARCHAR(140) NOT NULL,
  description VARCHAR(255) NULL,
  is_system   TINYINT(1) NOT NULL DEFAULT 0,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_template_company_slug (company_id, slug),
  CONSTRAINT fk_tpl_company FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS permission_template_items (
  template_id   BIGINT UNSIGNED NOT NULL,
  permission_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (template_id, permission_id),
  KEY idx_tpi_permission (permission_id),
  CONSTRAINT fk_tpi_template FOREIGN KEY (template_id) REFERENCES permission_templates (id) ON DELETE CASCADE,
  CONSTRAINT fk_tpi_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Audit logs — every permission / entity change is recorded here.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  company_id    BIGINT UNSIGNED NULL,
  actor_id      BIGINT UNSIGNED NULL,             -- who performed the action
  actor_name    VARCHAR(150) NULL,                -- denormalised for durability
  action        VARCHAR(80) NOT NULL,             -- e.g. permissions.update, company.create
  entity_type   VARCHAR(60) NULL,                 -- user | role | company | template ...
  entity_id     BIGINT UNSIGNED NULL,
  target_user_id BIGINT UNSIGNED NULL,
  changes       JSON NULL,                        -- { added: [...], removed: [...], ... }
  ip_address    VARCHAR(64) NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_audit_company (company_id),
  KEY idx_audit_actor (actor_id),
  KEY idx_audit_action (action),
  KEY idx_audit_target (target_user_id),
  KEY idx_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Domain tables: teams, projects, tasks (so permissions guard real resources)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS teams (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  company_id  BIGINT UNSIGNED NOT NULL,
  name        VARCHAR(150) NOT NULL,
  deleted_at  DATETIME NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_teams_company (company_id),
  CONSTRAINT fk_teams_company FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS team_members (
  team_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  -- lead / assistant_lead / member designation WITHIN this team
  role_in_team ENUM('lead','assistant_lead','member') NOT NULL DEFAULT 'member',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (team_id, user_id),
  KEY idx_tm_user (user_id),
  KEY idx_tm_role (team_id, role_in_team),
  CONSTRAINT fk_tm_team FOREIGN KEY (team_id) REFERENCES teams (id) ON DELETE CASCADE,
  CONSTRAINT fk_tm_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS projects (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  company_id  BIGINT UNSIGNED NOT NULL,
  team_id     BIGINT UNSIGNED NULL,
  name        VARCHAR(150) NOT NULL,
  status      ENUM('active','archived') NOT NULL DEFAULT 'active',
  deleted_at  DATETIME NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_projects_company (company_id),
  KEY idx_projects_team (team_id),
  CONSTRAINT fk_projects_company FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE,
  CONSTRAINT fk_projects_team FOREIGN KEY (team_id) REFERENCES teams (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- task_statuses: DYNAMIC, per-company status set (replaces the old ENUM).
-- Team leads / admins can add statuses; each carries a note (description).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS task_statuses (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  company_id  BIGINT UNSIGNED NOT NULL,
  name        VARCHAR(80) NOT NULL,
  note        VARCHAR(255) NULL,               -- the "description as note" from the spec
  color       VARCHAR(20) NOT NULL DEFAULT 'grey',
  sort_order  INT NOT NULL DEFAULT 0,
  is_default  TINYINT(1) NOT NULL DEFAULT 0,   -- status new tasks get
  is_done     TINYINT(1) NOT NULL DEFAULT 0,   -- terminal / completed bucket
  created_by  BIGINT UNSIGNED NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_status_company_name (company_id, name),
  KEY idx_status_company (company_id),
  CONSTRAINT fk_status_company FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE,
  CONSTRAINT fk_status_creator FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tasks (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  company_id   BIGINT UNSIGNED NOT NULL,
  team_id      BIGINT UNSIGNED NULL,
  project_id   BIGINT UNSIGNED NULL,
  parent_id    BIGINT UNSIGNED NULL,            -- non-null => this row is a subtask
  title        VARCHAR(200) NOT NULL,
  heading      VARCHAR(255) NULL,               -- "task heading" (sub-title / summary line)
  description  TEXT NULL,
  status_id    BIGINT UNSIGNED NULL,            -- dynamic status (task_statuses)
  priority     ENUM('low','medium','high','urgent') NOT NULL DEFAULT 'medium',
  assignee_id  BIGINT UNSIGNED NULL,
  created_by   BIGINT UNSIGNED NULL,
  due_date     DATE NULL,
  deleted_at   DATETIME NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_tasks_company (company_id),
  KEY idx_tasks_team (team_id),
  KEY idx_tasks_project (project_id),
  KEY idx_tasks_parent (parent_id),
  KEY idx_tasks_assignee (assignee_id),
  KEY idx_tasks_status (status_id),
  KEY idx_tasks_created (created_at),
  CONSTRAINT fk_tasks_company FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE,
  CONSTRAINT fk_tasks_team FOREIGN KEY (team_id) REFERENCES teams (id) ON DELETE SET NULL,
  CONSTRAINT fk_tasks_project FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE SET NULL,
  CONSTRAINT fk_tasks_parent FOREIGN KEY (parent_id) REFERENCES tasks (id) ON DELETE CASCADE,
  CONSTRAINT fk_tasks_status FOREIGN KEY (status_id) REFERENCES task_statuses (id) ON DELETE SET NULL,
  CONSTRAINT fk_tasks_assignee FOREIGN KEY (assignee_id) REFERENCES users (id) ON DELETE SET NULL,
  CONSTRAINT fk_tasks_creator FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- task_comments
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS task_comments (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  task_id     BIGINT UNSIGNED NOT NULL,
  user_id     BIGINT UNSIGNED NULL,
  body        TEXT NOT NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_tc_task (task_id),
  CONSTRAINT fk_tc_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
  CONSTRAINT fk_tc_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- task_attachments (file metadata; bytes live on disk under /uploads)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS task_attachments (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  task_id       BIGINT UNSIGNED NOT NULL,
  uploaded_by   BIGINT UNSIGNED NULL,
  original_name VARCHAR(255) NOT NULL,
  stored_name   VARCHAR(255) NOT NULL,
  mime_type     VARCHAR(120) NULL,
  size_bytes    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_ta_task (task_id),
  CONSTRAINT fk_ta_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
  CONSTRAINT fk_ta_user FOREIGN KEY (uploaded_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- task_shares: a single task made visible to a specific user
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS task_shares (
  task_id     BIGINT UNSIGNED NOT NULL,
  user_id     BIGINT UNSIGNED NOT NULL,
  granted_by  BIGINT UNSIGNED NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (task_id, user_id),
  KEY idx_ts_user (user_id),
  CONSTRAINT fk_ts_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
  CONSTRAINT fk_ts_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_ts_granter FOREIGN KEY (granted_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- task_list_shares: viewer can see ALL of owner's tasks ("show this list")
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS task_list_shares (
  company_id  BIGINT UNSIGNED NOT NULL,
  owner_id    BIGINT UNSIGNED NOT NULL,        -- whose tasks are exposed
  viewer_id   BIGINT UNSIGNED NOT NULL,        -- who may see them
  granted_by  BIGINT UNSIGNED NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (owner_id, viewer_id),
  KEY idx_tls_viewer (viewer_id),
  KEY idx_tls_company (company_id),
  CONSTRAINT fk_tls_company FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE,
  CONSTRAINT fk_tls_owner FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_tls_viewer FOREIGN KEY (viewer_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_tls_granter FOREIGN KEY (granted_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;
