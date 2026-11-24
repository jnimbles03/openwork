# Auth Routes

This folder owns authentication-related HTTP surfaces.

## Files

- `index.ts`: mounts Better Auth at `/api/auth/*` and registers auth-specific route groups
- `desktop-handoff.ts`: desktop sign-in handoff flow under `/v1/auth/desktop-handoff*`

## Current responsibilities

- forward Better Auth requests to `auth.handler(c.req.raw)`
- create short-lived desktop handoff grants
- exchange a valid handoff grant for a session token

## Expected dependencies

- Better Auth configuration from `src/auth.ts`
- shared auth/session middleware from `src/session.ts`
- request validation from `src/middleware/index.ts`

## Notes for future work

- Keep browser auth routes mounted through Better Auth unless there is a strong reason to wrap them
- Over HTTP, the Better Auth organization plugin only serves `/api/auth/organization/set-active`; its other endpoints return 403 (see `src/auth.ts`). Organization, member, invitation, team, and role changes go through the Den `/v1` routes, which enforce plan limits and org policies.
- Organization `metadata` is server-owned (it holds plan limits). Better Auth organization create/update rejects any client-supplied `metadata`.
- Put new auth-adjacent custom endpoints in this folder, not in `me/` or `org/`
