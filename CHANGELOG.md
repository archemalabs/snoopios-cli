# Changelog

## 0.7.0 (13 October 2026)

Every provider below has now been run against a real account, and several of the
providers already in 0.6.0 were wrong when they first met one. If you use 0.6.0,
upgrade: the fixes change verdicts.

### Eight new providers for `run`
- `snyk` (SNYK_TOKEN, SNYK_ORG_ID), `semgrep` (SEMGREP_APP_TOKEN, SEMGREP_DEPLOYMENT) and
  `aikido` (AIKIDO_CLIENT_ID, AIKIDO_CLIENT_SECRET): your scanner's own findings, read and
  never re-run. Nothing critical open, serious findings closed within thirty days,
  nothing open past ninety, projects scanned in the last fortnight.
- `gitguardian` (GITGUARDIAN_API_KEY with incidents:read and sources:read): no committed
  credential still valid, no critical incident open, incidents closed in time.
- `sonarqube` (SONAR_TOKEN, SONAR_PROJECT_KEY, and SONAR_HOST_URL when self-hosted): a
  quality gate that passes and tests something, a recent analysis, security rating A.
- `onepassword` (OP_EVENTS_TOKEN, OP_REGION): second factors actually used at sign-in, no
  account being guessed at, an audit log you can produce.
- `bitwarden` (BW_CLIENT_ID, BW_CLIENT_SECRET, and BW_REGION=eu for bitwarden.eu): second
  factors held and required, company items owned by the company, least privilege on
  collections, nobody stuck halfway through joining.
- `doppler` (DOPPLER_TOKEN, a personal token): no service token that can write, none on a
  root config, none older than a year.

### Verdicts that changed (each check's version is bumped)
- Netlify: HTTPS on a default netlify.app address was failed because the fields read
  describe a custom domain's certificate; site protection could never answer, and now
  recognises Netlify's own login as well as a password.
- Neon: projects are listed per organisation; the first version asked an endpoint that
  returns nothing for organisation-owned projects.
- Render: no custom domain is unknown rather than a pass, and a service using the
  workspace's default notifications is judged by the workspace's settings.
- Clerk: an empty redirect allowlist is unknown rather than a pass.
- CircleCI: a project connected through the GitHub App is named as such instead of being
  blamed on the token.
- `scan`: a 401, 403, 407, 429 or 451 from the site is unknown, not a failing site; DMARC
  no longer reads `sp=` as `p=`; MTA-STS checks what a sending server actually checks.
- `repo`: the history scan no longer reports a value it should have recognised as a
  placeholder.

### Safer
- `doctor` verifies the database server's certificate: Supabase's own root for
  `*.supabase.com`, your system's roots otherwise. 0.6.0 did not, so it would have sent
  the password to a server that only claimed to be yours. A connection error now names
  the likely cause instead of always blaming the certificate.
- The bundle carries only the checks the CLI can run. 0.6.0 also carried every hosted
  connector's code, unreachable but there for an auditor to wonder about: 906 KB down to
  667 KB.

## 0.6.0 (8 September 2026)
- `snoopios run circleci` (CIRCLECI_TOKEN and CIRCLECI_PROJECT such as gh/org/repo): builds
  hidden from the public, settings changed by admins only, forks do not receive secrets.
- `snoopios run checkly` (CHECKLY_API_KEY and CHECKLY_ACCOUNT_ID): checks present and none
  muted, every check alerts somebody, certificate expiry alerts on, checks from more than
  one location.
- `snoopios run turso` (TURSO_API_TOKEN and TURSO_ORG): delete protection on every database
  and group, owners held by few.
- `snoopios run workos` (WORKOS_API_KEY): SSO connections live, directory syncs healthy,
  customer domains verified, user emails verified.

## 0.5.0 (8 September 2026)
- `--push` on `run` and `repo`: posts the results (check, status, observed values,
  evidence) to your Snoopios project with the key in `SNOOPIOS_INGEST_KEY`, created on the
  project page under Run locally and push. The provider token still never leaves the
  machine. Results are labelled Run by you on the check page, in every document and on
  the trust page; `--ci` (or GitHub Actions / GitLab CI, detected) labels them Run in CI
  and records the run URL.
- README: an hourly GitHub Actions workflow and a cron line.

## 0.4.0 (8 September 2026)
- `snoopios run upstash` (UPSTASH_EMAIL and UPSTASH_API_KEY): TLS on every Redis database,
  daily backups on paid ones, nothing suspended. Database credentials in the API response
  are dropped before anything is printed.
- `snoopios run betterstack` (BETTERSTACK_API_TOKEN): monitors present and none paused,
  certificate checks on HTTPS monitors, checks at least every five minutes, every monitor
  alerting somebody.
- `snoopios run railway` (RAILWAY_TOKEN, a project token): health check on every public
  service, restart policy not Never, more than one replica, custom domains pointing at
  Railway. Variables are never read.

## 0.3.1 (8 September 2026)
- `repo`: a credential shape inside a test path (`*.test.*`, `*.spec.*`, `fixtures/`,
  `__tests__/` and the like) is listed by path and shape but no longer fails the check on
  its own. The verdict rests on the rest of the history. Check version 2.
- `repo`: `npm audit` runs through npm's own entry point beside node, without a shell.

## 0.3.0 (8 September 2026)
- `snoopios repo [path]`: seven checks on a git checkout with no token and on any host:
  tracked .env files, .gitignore coverage, credential shapes in the full history (the
  result names the shape, never the value), lockfiles, SECURITY.md and CODEOWNERS,
  Dependabot or Renovate, and `npm audit` for critical or high findings.
- `snoopios run heroku` (four checks: managed certificates, maintenance mode, supported
  stacks, web tier redundancy) and `snoopios run clerk` (three checks: HTTPS-only redirect
  URLs, JWT template lifetimes, dormant users) from `HEROKU_API_KEY` and
  `CLERK_SECRET_KEY`.
- A lockfile ships with the package and Dependabot watches its dependency.

## 0.2.1 (8 September 2026)
- Package metadata points at this repository.

## 0.2.0 (8 September 2026)
- `snoopios run netlify|neon|render`: eleven checks for providers whose tokens cannot be
  made read-only, run on your machine from `NETLIFY_AUTH_TOKEN`, `NEON_API_KEY` or
  `RENDER_API_KEY`. The token never leaves your machine.
- `snoopios doctor <postgres-url>`: the five Supabase SQL checks against any connection
  string. SELECT statements only.

## 0.1.0 (7 September 2026)
- `snoopios scan <domain>`: eleven domain checks, plus six sending-domain checks with
  `--email <provider>`. `--json` output. Exit code 1 on any fail.
