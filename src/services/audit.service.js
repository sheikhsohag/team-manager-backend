'use strict';

/**
 * Audit logging. Every permission/entity change funnels through here so the
 * super-admin audit log and the per-user "permission change history" are
 * complete and tamper-evident (append-only).
 */

const { execute, query } = require('../config/db');

/**
 * @param {object} entry
 * @param {object} entry.actor     - req.user (id, name, company_id)
 * @param {string} entry.action    - e.g. 'permissions.update', 'company.create'
 * @param {string} [entry.entityType]
 * @param {number} [entry.entityId]
 * @param {number} [entry.targetUserId]
 * @param {object} [entry.changes]  - arbitrary JSON (added/removed/before/after)
 * @param {number} [entry.companyId]
 * @param {string} [entry.ip]
 */
async function record(entry) {
  const {
    actor, action, entityType = null, entityId = null,
    targetUserId = null, changes = null, companyId = null, ip = null,
  } = entry;

  await execute(
    `INSERT INTO audit_logs
       (company_id, actor_id, actor_name, action, entity_type, entity_id, target_user_id, changes, ip_address)
     VALUES (:company_id, :actor_id, :actor_name, :action, :entity_type, :entity_id, :target_user_id, :changes, :ip)`,
    {
      company_id: companyId ?? (actor ? actor.company_id : null) ?? null,
      actor_id: actor ? actor.id : null,
      actor_name: actor ? actor.name : 'system',
      action,
      entity_type: entityType,
      entity_id: entityId,
      target_user_id: targetUserId,
      changes: changes ? JSON.stringify(changes) : null,
      ip,
    }
  );
}

async function list({ companyId, targetUserId, action, limit = 100, offset = 0 } = {}) {
  const where = [];
  const params = {};
  if (companyId) { where.push('company_id = :companyId'); params.companyId = companyId; }
  if (targetUserId) { where.push('target_user_id = :targetUserId'); params.targetUserId = targetUserId; }
  if (action) { where.push('action = :action'); params.action = action; }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  // LIMIT/OFFSET are inlined as validated integers — prepared-statement
  // placeholders for LIMIT are unreliable across MySQL versions.
  const lim = Math.max(1, Math.min(Number(limit) || 100, 1000));
  const off = Math.max(0, Number(offset) || 0);

  const rows = await query(
    `SELECT * FROM audit_logs ${clause} ORDER BY created_at DESC, id DESC LIMIT ${lim} OFFSET ${off}`,
    params
  );
  return rows.map((r) => ({ ...r, changes: r.changes ? safeParse(r.changes) : null }));
}

function safeParse(v) {
  if (v == null) return null;
  if (typeof v === 'object') return v; // mysql2 may already return parsed JSON
  try { return JSON.parse(v); } catch { return v; }
}

module.exports = { record, list };
