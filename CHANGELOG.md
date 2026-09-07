# Changelog

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
