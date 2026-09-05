'use strict';

require('dotenv').config();
const app = require('./app');
const { pool } = require('./config/db');

const PORT = Number(process.env.PORT || 4000);

async function start() {
  try {
    // fail fast if the DB is unreachable
    const conn = await pool.getConnection();
    await conn.ping();
    conn.release();
    console.log('Database connection OK');
  } catch (err) {
    console.error('Could not connect to MySQL:', err.message);
    console.error('Check your .env DB_* settings and that MySQL is running.');
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`API listening on http://localhost:${PORT}`);
  });
}

start();
