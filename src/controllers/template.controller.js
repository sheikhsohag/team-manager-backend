'use strict';

const { query, queryOne, execute } = require('../config/db');
const audit = require('../services/audit.service');
const { asyncHandler } = require('../middleware/error');
const { clientIp } = require('./helpers');

function slugify(s) {
  return String(s).toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// GET /permission-templates
const list = asyncHandler(async (req, res) => {
  const params = {};
  let scope = 'company_id IS NULL';
  if (!req.user.is_super_admin) { scope = '(company_id IS NULL OR company_id = :c)'; params.c = req.user.company_id; }
  const rows = await query(
    `SELECT t.*, (SELECT COUNT(*) FROM permission_template_items i WHERE i.template_id = t.id) AS permission_count
       FROM permission_templates t WHERE ${scope} ORDER BY t.is_system DESC, t.name`,
    params
  );
  res.json({ templates: rows });
});

// GET /permission-templates/:id
const getOne = asyncHandler(async (req, res) => {
  const tpl = await queryOne('SELECT * FROM permission_templates WHERE id = :id', { id: req.params.id });
  if (!tpl) return res.status(404).json({ error: 'Template not found' });
  const perms = await query(
    `SELECT p.\`key\` FROM permission_template_items i JOIN permissions p ON p.id = i.permission_id
      WHERE i.template_id = :id`, { id: tpl.id }
  );
  res.json({ template: tpl, permissions: perms.map((p) => p.key) });
});

// POST /permission-templates  { name, description?, permissions[] }
const create = asyncHandler(async (req, res) => {
  const { name, description = null, permissions = [] } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });
  const companyId = req.user.is_super_admin ? (req.body.companyId || null) : req.user.company_id;
  const slug = slugify(name);
  const result = await execute(
    `INSERT INTO permission_templates (company_id, name, slug, description, is_system)
     VALUES (:c, :n, :s, :d, 0)`,
    { c: companyId, n: name, s: slug, d: description }
  );
  const tplId = result.insertId;
  for (const key of permissions) {
    const p = await queryOne('SELECT id FROM permissions WHERE `key` = :k', { k: key });
    if (p) await execute('INSERT IGNORE INTO permission_template_items (template_id, permission_id) VALUES (:t, :p)', { t: tplId, p: p.id });
  }
  await audit.record({
    actor: req.user, action: 'template.create', entityType: 'template', entityId: tplId,
    companyId, changes: { name, permissions }, ip: clientIp(req),
  });
  res.status(201).json({ id: tplId, slug });
});

// DELETE /permission-templates/:id
const remove = asyncHandler(async (req, res) => {
  const tpl = await queryOne('SELECT * FROM permission_templates WHERE id = :id', { id: req.params.id });
  if (!tpl) return res.status(404).json({ error: 'Template not found' });
  if (tpl.is_system) return res.status(400).json({ error: 'System templates cannot be deleted' });
  if (!req.user.is_super_admin && Number(tpl.company_id) !== Number(req.user.company_id)) {
    return res.status(403).json({ error: 'Cross-company access denied' });
  }
  await execute('DELETE FROM permission_templates WHERE id = :id', { id: tpl.id });
  res.json({ ok: true });
});

module.exports = { list, getOne, create, remove };
