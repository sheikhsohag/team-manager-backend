# Backend — Task Manager API

Node.js + Express + MySQL. JWT auth. Permission engine with role + user overrides +
company boundary, audit logging, and an in-memory effective-permission cache.

## Setup

```bash
cp .env.example .env      # set DB creds + SUPER_ADMIN_* + JWT_SECRET
npm install
npm run migrate           # apply src/db/schema.sql
npm run seed              # groups, permissions, roles, templates, super admin, demo
npm run dev               # http://localhost:4000
```

`npm run db:reset` drops + recreates + reseeds (development only).

## Auth

```
POST /api/auth/login   { email, password }  ->  { token, user }
GET  /api/auth/me      (Bearer token)        ->  { user, roles, allowedKeys, summary }
```

Send `Authorization: Bearer <token>` on every other call.

## Permission engine (`src/services/permission.service.js`)

`computeEffective(userId)` returns a decision for **every** permission with a `source`:

| source | meaning |
| --- | --- |
| `Super Admin` | user is super admin → always allow |
| `System Policy` | system-only permission, denied to normal users |
| `Company Policy` | disabled by the company boundary |
| `User Override` | explicit per-user ALLOW/DENY |
| `Role` | granted by an assigned role (`sourceDetail` = role name) |
| `Not assigned` | default deny |

`can(userId, key)` powers the `can('...')` middleware. Results are cached per user and
invalidated on any role/user/company/permission change.

## Enforcement

Every mutating route is guarded on the backend, e.g.

```js
router.delete('/tasks/:id', authenticate, can('task.delete'), task.remove);
```

Unauthorized requests get **HTTP 403** with the missing permission name. The frontend
never enforces — it only hides/disables UI.

## Key endpoints

- `GET  /api/permissions` — full catalog grouped by module
- `GET  /api/users/:id/effective-permissions` — matrix + sources + summary
- `PUT  /api/users/:id/permissions` — `{ changes: [{ key, effect: allow|deny|inherit }] }`
- `POST /api/users/:id/permissions/reset` — reset overrides to role defaults
- `POST /api/users/:id/permissions/apply-template` — `{ templateId, mode }`
- `POST /api/permissions/simulate` — `{ userId, permission }` → allow/deny + reason
- `POST /api/permissions/copy` — `{ fromUserId, toUserId }`
- `POST /api/permissions/bulk` — assign role / add / remove permission for many users
- `GET  /api/super-admin/admins` — admin table with live allowed/denied counts
- `GET/PUT /api/super-admin/companies/:id/permissions` — company boundary
- `GET/PUT /api/roles/:id/permissions` — role permission set
- `GET  /api/super-admin/audit-logs` — permission change history
