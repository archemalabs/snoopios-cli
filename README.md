# snoopios

The checks [Snoopios](https://snoopios.com) runs every hour for its customers, run once
from your own machine. Every check returns `pass`, `fail` or `unknown`, and unknown is
never a pass. Exit code 1 when anything fails, so it sits in CI. Nothing is sent to
Snoopios or anyone else.

## scan a domain

```bash
npx snoopios scan example.com
```

HTTPS redirect, HSTS, a Content-Security-Policy that stops exfiltration, the basic
hardening headers, TLS version and certificate expiry, HSTS preload, SPF, DMARC, CAA,
security.txt and a privacy page that names a controller and a date. Add `--email resend`
(or `postmark`, `mailgun`, `ses`, `other`) for the sending domain: DKIM, SPF on the
return path, DMARC enforcement and reporting, MTA-STS and TLS-RPT.

## run a provider whose token cannot be made read-only

```bash
NETLIFY_AUTH_TOKEN=… npx snoopios run netlify
NEON_API_KEY=…       npx snoopios run neon
RENDER_API_KEY=…     npx snoopios run render
HEROKU_API_KEY=…     npx snoopios run heroku
CLERK_SECRET_KEY=…   npx snoopios run clerk
UPSTASH_EMAIL=… UPSTASH_API_KEY=… npx snoopios run upstash
BETTERSTACK_API_TOKEN=… npx snoopios run betterstack
RAILWAY_TOKEN=…      npx snoopios run railway
```

These providers' tokens cannot be scoped read-only (Upstash's can, but nothing reads that
back and its API returns database credentials), so Snoopios never holds them. The
CLI reads the token from your environment, runs the checks here and prints the report.
The token never leaves your machine, and every request is a read.

- **Netlify**: HTTPS forced on every site, sites behind site protection, secret-looking
  variables marked secret, live sites sending the basic hardening headers.
- **Neon**: database reachable only from listed addresses, production branch protected,
  at least seven days of point-in-time restore, no preview branch older than thirty days.
- **Render**: a health check on every web service, every custom domain verified, deploy
  failures not ignored.
- **Heroku**: a certificate on every custom domain, no app left in maintenance mode, every
  app on a supported stack, the web tier on more than one dyno.
- **Clerk**: redirect URLs HTTPS and not local, JWT templates expiring within an hour, no
  dormant account able to sign in.
- **Upstash**: TLS on every Redis database, daily backups on paid ones, nothing suspended.
  Credentials in the API response are dropped before anything is printed.
- **Better Stack**: monitors present and none paused, certificate checks on HTTPS monitors,
  checks at least every five minutes, every monitor alerting somebody.
- **Railway** (project token): health check on every public service, restart policy not
  Never, more than one replica, custom domains pointing at Railway. Variables are never
  read.

## check a git checkout

```bash
npx snoopios repo .
```

No token, any git host. Tracked .env files, .gitignore coverage, credential shapes anywhere
in the full history (the result names the shape, never the value), a lockfile beside every
manifest, SECURITY.md and CODEOWNERS, Dependabot or Renovate configuration, and `npm audit`
for critical or high findings. Only the audit touches the network.

## doctor a Postgres database

```bash
npx snoopios doctor postgres://user:pass@host:5432/db
```

The Supabase SQL checks against any connection string you already have, including a
local Supabase: row-level security on every public table, no policy that lets anon
write, the private schema closed to session roles, `SECURITY DEFINER` functions pinning
`search_path`, and anon-callable definers that are safe to expose. SELECT statements
only. Also reads `DATABASE_URL` when no argument is given.

## output

`--json` prints the observed facts for every check. Each fail comes with the fix. To keep
it all checked every hour, with stored evidence, accepted risks and a public trust page,
connect at https://snoopios.com.

Source of the published bundle, changelog and security policy:
https://github.com/archemalabs/snoopios-cli

MIT © Archema Labs Ltd
