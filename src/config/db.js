'use strict';

/**
 * MySQL connection pool + thin query helpers.
 *
 * We use raw parameterised SQL (mysql2) rather than an ORM so the permission
 * schema (foreign keys, unique constraints, indexes) is explicit and auditable.
 */

const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'task_manager',
  waitForConnections: true,
  connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
  queueLimit: 0,
  multipleStatements: false,
  namedPlaceholders: true,
  charset: 'utf8mb4_unicode_ci',
});

/** Run a query and return the rows. */
async function query(sql, params = {}) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

/** Run a query and return a single row (or null). */
async function queryOne(sql, params = {}) {
  const rows = await query(sql, params);
  return rows.length ? rows[0] : null;
}

/** Run an INSERT/UPDATE/DELETE and return the raw ResultSetHeader. */
async function execute(sql, params = {}) {
  const [result] = await pool.execute(sql, params);
  return result;
}

/**
 * Run a set of statements inside a transaction.
 * `fn` receives a connection with the same query/queryOne/execute helpers.
 */
async function transaction(fn) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const helpers = {
      query: async (sql, params = {}) => {
        const [rows] = await conn.execute(sql, params);
        return rows;
      },
      queryOne: async (sql, params = {}) => {
        const [rows] = await conn.execute(sql, params);
        return rows.length ? rows[0] : null;
      },
      execute: async (sql, params = {}) => {
        const [result] = await conn.execute(sql, params);
        return result;
      },
    };
    const out = await fn(helpers);
    await conn.commit();
    return out;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

module.exports = { pool, query, queryOne, execute, transaction };
