# AGENTS.md

## Repo Purpose

This repository contains `my-oauth`, a Cloudflare Worker that acts as a Google OAuth 2.0 proxy for related frontend apps. It owns login, callback handling, session cookies, token refresh, profile lookup, logout, and authenticated proxying to a configured Google Apps Script backend.

Read these memory docs before changing behavior:

- [doc/project-memory.md](doc/project-memory.md)
- [doc/architecture.md](doc/architecture.md)
- [doc/operations.md](doc/operations.md)
- [doc/decisions-and-risks.md](doc/decisions-and-risks.md)

## Important Commands

- `npm start` or `npm run dev`: start local Wrangler dev server.
- `npm run deploy`: deploy with Wrangler.
- `npm test`: run Vitest tests when tests exist.
- `npm run cf-typegen`: generate Cloudflare Worker environment typings.

## Code Map

- `src/index.ts`: all Worker routes and OAuth/session/proxy behavior.
- `wrangler.jsonc`: Worker entrypoint, compatibility date, observability, and KV binding.
- `.github/workflows/deploy.yml`: deploys the Worker on pushes to `main`.
- `README.md`: user-facing behavior and route documentation.

## Project Constraints

- Runtime is Cloudflare Workers. Use Web APIs and Worker-compatible dependencies.
- Sessions and app configuration are stored in the `TOKEN_STORE` KV binding.
- Google client credentials must stay in secrets/env values, not source files.
- Cookie behavior is security-sensitive. Existing cookies use `secure`, `sameSite: "lax"`, `path: "/"`, and domain `josephtseng-tw.com`.
- App-specific access is controlled by KV entries named `config:<app_id>`.
- Allowed redirect origins and CORS origins must come from each app config's `allowed_origins`.

## Before Editing

- Check `git status --short` and do not overwrite unrelated user changes.
- Keep changes scoped; this repo currently has a single Worker entrypoint and no broader app framework.
- Update docs when route behavior, KV schema, cookie policy, deployment, or security assumptions change.
- If adding tests, prefer focused coverage around auth errors, CORS, cookie headers, session refresh, and proxy request construction.

## Known Follow-Up

`tsconfig.json` references `worker-configuration.d.ts`, but that file is not currently present in the repo. Run `npm run cf-typegen` when Cloudflare environment typings are needed.
