'use strict';

/**
 * Applies src/db/schema.sql to the configured database.
 *
 *   node src/db/migrate.js          -> create tables (idempotent, CREATE IF NOT EXISTS)
 *   node src/db/migrate.js --drop   -> drop all known tables first, then recreate
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

const TABLES_IN_DROP_ORDER = [
  'tasks', 'projects', 'team_members', 'teams',
  'audit_logs',
  'permission_template_items', 'permission_templates',
  'company_permissions', 'company_roles',
  'user_permissions', 'user_roles', 'role_permissions',
  'roles', 'permissions', 'permission_groups',
  'users', 'companies',
];

async function main() {
  const drop = process.argv.includes('--drop');
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'task_manager',
    multipleStatements: true,
  });

  try {
    if (drop) {
      console.log('Dropping existing tables...');
      await conn.query('SET FOREIGN_KEY_CHECKS = 0;');
      for (const t of TABLES_IN_DROP_ORDER) {
        await conn.query(`DROP TABLE IF EXISTS \`${t}\`;`);
      }
      await conn.query('SET FOREIGN_KEY_CHECKS = 1;');
    }

    const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    console.log('Applying schema.sql ...');
    await conn.query(sql);
    console.log('Migration complete.');
  } catch (err) {
    console.error('Migration failed:', err.message);
    process.exitCode = 1;
  } finally {
    await conn.end();
  }
}

main();
