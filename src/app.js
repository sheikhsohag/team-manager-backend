'use strict';

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const routes = require('./routes');
const { errorHandler, notFound } = require('./middleware/error');

const app = express();

const allowList = (process.env.CORS_ORIGIN || 'http://localhost:3000')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const isDev = process.env.NODE_ENV !== 'production';

// Matches localhost, 127.0.0.1 and private-LAN IPs (any port) — dev only.
const LAN_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1|(?:192\.168|10)\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(:\d+)?$/;

function corsOrigin(origin, cb) {
  // Requests with no Origin header (curl, same-origin, mobile apps) are allowed.
  if (!origin) return cb(null, true);
  if (allowList.includes(origin)) return cb(null, true);
  if (isDev && LAN_ORIGIN.test(origin)) return cb(null, true);
  return cb(new Error(`Not allowed by CORS: ${origin}`));
}

app.use(cors({ origin: corsOrigin, credentials: true }));
app.use(express.json({ limit: '1mb' }));
if (process.env.NODE_ENV !== 'test') app.use(morgan('dev'));

app.get('/health', (req, res) => res.json({ ok: true, service: 'task-manager-api' }));

app.use('/api', routes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
