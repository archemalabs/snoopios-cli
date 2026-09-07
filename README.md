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
```

Netlify, Neon and Render tokens are all-or-nothing, so Snoopios never holds them. The
CLI reads the token from your environment, runs the checks here and prints the report.
The token never leaves your machine, and every request is a read.

- **Netlify**: HTTPS forced on every site, sites behind site protection, secret-looking
  variables marked secret, live sites sending the basic hardening headers.
- **Neon**: database reachable only from listed addresses, production branch protected,
  at least seven days of point-in-time restore, no preview branch older than thirty days.
- **Render**: a health check on every web service, every custom domain verified, deploy
  failures not ignored.

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

MIT © Archema Labs Ltd
