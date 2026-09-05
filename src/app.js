'use strict';

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const routes = require('./routes');
const { errorHandler, notFound } = require('./middleware/error');

const app = express();

const origins = (process.env.CORS_ORIGIN || 'http://localhost:3000')
  .split(',')
  .map((s) => s.trim());

app.use(cors({ origin: origins, credentials: true }));
app.use(express.json({ limit: '1mb' }));
if (process.env.NODE_ENV !== 'test') app.use(morgan('dev'));

app.get('/health', (req, res) => res.json({ ok: true, service: 'task-manager-api' }));

app.use('/api', routes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
