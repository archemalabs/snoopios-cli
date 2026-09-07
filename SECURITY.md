# Security

This repository holds the published bundle of the `snoopios` CLI, exactly as shipped to
npm, so that anyone can read what `npx snoopios` runs before running it.

What the CLI does and does not do:

- Every request is a read. The bundle carries the same guard the Snoopios product uses,
  which refuses any HTTP method that could change something at a provider.
- Nothing is sent to Snoopios. The only hosts contacted are the domain you name,
  Cloudflare's DNS-over-HTTPS resolver, hstspreload.org, and, for `run`, the vendor API of
  the provider you chose. `doctor` connects to the Postgres URL you give it and runs
  SELECT statements.
- Tokens for `run` are read from your environment and are never written, logged or
  transmitted anywhere except to that vendor's API over HTTPS.

To report a vulnerability, email hello@snoopios.com. We acknowledge within two working
days. Please do not open a public issue for a security report.
