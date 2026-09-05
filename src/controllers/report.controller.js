'use strict';

const { query, queryOne } = require('../config/db');
const audit = require('../services/audit.service');
const { asyncHandler } = require('../middleware/error');
const { clientIp } = require('./helpers');

function scope(req) {
  return req.user.is_super_admin && req.query.companyId ? Number(req.query.companyId) : req.user.company_id;
}

// GET /reports — requires report.view
const summary = asyncHandler(async (req, res) => {
  const companyId = scope(req);
  const where = companyId ? 'WHERE company_id = :c AND deleted_at IS NULL' : 'WHERE deleted_at IS NULL';
  const params = companyId ? { c: companyId } : {};
  const byStatus = await query(
    `SELECT status, COUNT(*) AS n FROM tasks ${where} GROUP BY status`, params
  );
  const totals = await queryOne(
    `SELECT COUNT(*) AS tasks,
            SUM(status='done') AS done,
            SUM(status='in_progress') AS in_progress
       FROM tasks ${where}`, params
  );
  res.json({ byStatus, totals });
});

// POST /reports/generate — requires report.generate
const generate = asyncHandler(async (req, res) => {
  const companyId = scope(req);
  const rows = await query(
    `SELECT status, priority, COUNT(*) AS n FROM tasks
      WHERE deleted_at IS NULL ${companyId ? 'AND company_id = :c' : ''}
      GROUP BY status, priority`,
    companyId ? { c: companyId } : {}
  );
  await audit.record({ actor: req.user, action: 'report.generate', entityType: 'report', companyId, ip: clientIp(req) });
  res.json({ generatedAt: new Date().toISOString(), rows });
});

// GET /reports/export — requires report.export  (returns CSV)
const exportCsv = asyncHandler(async (req, res) => {
  const companyId = scope(req);
  const rows = await query(
    `SELECT id, title, status, priority FROM tasks
      WHERE deleted_at IS NULL ${companyId ? 'AND company_id = :c' : ''} ORDER BY id`,
    companyId ? { c: companyId } : {}
  );
  await audit.record({ actor: req.user, action: 'report.export', entityType: 'report', companyId, ip: clientIp(req) });
  const header = 'id,title,status,priority';
  const body = rows.map((r) => `${r.id},"${String(r.title).replace(/"/g, '""')}",${r.status},${r.priority}`).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="tasks-report.csv"');
  res.send(`${header}\n${body}`);
});

module.exports = { summary, generate, exportCsv };
