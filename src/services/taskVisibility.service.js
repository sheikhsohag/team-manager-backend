'use strict';

/**
 * Task visibility rules for a non-super-admin, non-view_all user.
 *
 * A user may see a task when ANY of these hold:
 *   - they are the assignee or the creator                     (own tasks)
 *   - the task was individually shared with them               (task_shares)
 *   - the task's owner shared their whole list with them       (task_list_shares)
 *   - they lead / co-lead the task's team                      (team visibility)
 *
 * Admins hold `task.view_all` and bypass this entirely (see controller).
 */

const { queryOne } = require('../config/db');

/**
 * Boolean SQL fragment (on table alias `t`) selecting tasks the user may see.
 * All sub-selects reuse the single :me parameter.
 */
function visibilityClause() {
  return (
    '(' +
    [
      't.assignee_id = :me',
      't.created_by = :me',
      't.id IN (SELECT task_id FROM task_shares WHERE user_id = :me)',
      't.assignee_id IN (SELECT owner_id FROM task_list_shares WHERE viewer_id = :me)',
      't.created_by IN (SELECT owner_id FROM task_list_shares WHERE viewer_id = :me)',
      "t.team_id IN (SELECT team_id FROM team_members WHERE user_id = :me AND role_in_team IN ('lead','assistant_lead'))",
    ].join(' OR ') +
    ')'
  );
}

/** Can this user see this already-loaded task row? */
async function canSee(user, task, hasViewAll) {
  if (user.is_super_admin) return true;
  if (Number(task.company_id) !== Number(user.company_id)) return false;
  if (hasViewAll) return true;
  if (Number(task.assignee_id) === Number(user.id)) return true;
  if (Number(task.created_by) === Number(user.id)) return true;

  const hit = await queryOne(
    `SELECT 1 AS ok FROM tasks t
      WHERE t.id = :id AND ${visibilityClause()} LIMIT 1`,
    { id: task.id, me: user.id }
  );
  return !!hit;
}

module.exports = { visibilityClause, canSee };
