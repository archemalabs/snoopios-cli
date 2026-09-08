# Changelog

## 0.6.0 — 8 September 2026
- `snoopios run circleci` (CIRCLECI_TOKEN and CIRCLECI_PROJECT such as gh/org/repo): builds
  hidden from the public, settings changed by admins only, forks do not receive secrets.
- `snoopios run checkly` (CHECKLY_API_KEY and CHECKLY_ACCOUNT_ID): checks present and none
  muted, every check alerts somebody, certificate expiry alerts on, checks from more than
  one location.
- `snoopios run turso` (TURSO_API_TOKEN and TURSO_ORG): delete protection on every database
  and group, owners held by few.
- `snoopios run workos` (WORKOS_API_KEY): SSO connections live, directory syncs healthy,
  customer domains verified, user emails verified.

## 0.5.0 — 8 September 2026
- `--push` on `run` and `repo`: posts the results (check, status, observed values,
  evidence) to your Snoopios project with the key in `SNOOPIOS_INGEST_KEY`, created on the
  project page under Run locally and push. The provider token still never leaves the
  machine. Results are labelled Run by you on the check page, in every document and on
  the trust page; `--ci` (or GitHub Actions / GitLab CI, detected) labels them Run in CI
  and records the run URL.
- README: an hourly GitHub Actions workflow and a cron line.

## 0.4.0 — 8 September 2026
- `snoopios run upstash` (UPSTASH_EMAIL and UPSTASH_API_KEY): TLS on every Redis database,
  daily backups on paid ones, nothing suspended. Database credentials in the API response
  are dropped before anything is printed.
- `snoopios run betterstack` (BETTERSTACK_API_TOKEN): monitors present and none paused,
  certificate checks on HTTPS monitors, checks at least every five minutes, every monitor
  alerting somebody.
- `snoopios run railway` (RAILWAY_TOKEN, a project token): health check on every public
  service, restart policy not Never, more than one replica, custom domains pointing at
  Railway. Variables are never read.

## 0.3.1 — 8 September 2026
- `repo`: a credential shape inside a test path (`*.test.*`, `*.spec.*`, `fixtures/`,
  `__tests__/` and the like) is listed by path and shape but no longer fails the check on
  its own. The verdict rests on the rest of the history. Check version 2.
- `repo`: `npm audit` runs through npm's own entry point beside node, without a shell.

## 0.3.0 — 8 September 2026
- `snoopios repo [path]`: seven checks on a git checkout with no token and on any host:
  tracked .env files, .gitignore coverage, credential shapes in the full history (the
  result names the shape, never the value), lockfiles, SECURITY.md and CODEOWNERS,
  Dependabot or Renovate, and `npm audit` for critical or high findings.
- `snoopios run heroku` (four checks: managed certificates, maintenance mode, supported
  stacks, web tier redundancy) and `snoopios run clerk` (three checks: HTTPS-only redirect
  URLs, JWT template lifetimes, dormant users) from `HEROKU_API_KEY` and
  `CLERK_SECRET_KEY`.
- A lockfile ships with the package and Dependabot watches its dependency.

## 0.2.1 — 8 September 2026
- Package metadata points at this repository.

## 0.2.0 — 8 September 2026
- `snoopios run netlify|neon|render`: eleven checks for providers whose tokens cannot be
  made read-only, run on your machine from `NETLIFY_AUTH_TOKEN`, `NEON_API_KEY` or
  `RENDER_API_KEY`. The token never leaves your machine.
- `snoopios doctor <postgres-url>`: the five Supabase SQL checks against any connection
  string. SELECT statements only.

## 0.1.0 — 7 September 2026
- `snoopios scan <domain>`: eleven domain checks, plus six sending-domain checks with
  `--email <provider>`. `--json` output. Exit code 1 on any fail.
