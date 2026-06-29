# domainintel

[![npm](https://img.shields.io/npm/v/@domainintel/cli.svg)](https://www.npmjs.com/package/@domainintel/cli)
[![license](https://img.shields.io/npm/l/@domainintel/cli.svg)](./LICENSE)
[![node](https://img.shields.io/node/v/@domainintel/cli.svg)](https://nodejs.org)

**Domain intelligence from your terminal.** One command runs WHOIS, DNS, SSL/TLS,
HTTP security headers, blocklist reputation and subdomain discovery against any
domain, prints a readable report, and exits non-zero when something's wrong, so it
drops straight into CI.

It's the command-line companion to [domainintel.app](https://domainintel.app) and
the [DomainIntel MCP server](https://www.npmjs.com/package/@domainintel/mcp), built
on the same analysis engine.

```
$ domainintel github.com

domainintel • github.com

Security score   A  81/100

WHOIS
────────────
  Registrar  MarkMonitor, Inc.
  Created    2007-10-09
  Expires    2026-10-09 (105 days)
  Privacy    disabled

SSL / TLS certificate
─────────────────────
  Issuer      Sectigo Limited
  Expires in  38 days
  Protocol    TLSv1.3

HTTP security headers
─────────────────────
  Grade  B (72%)
  ✓ strict-transport-security
  ✓ content-security-policy
  ...

✓ No issues detected.
```

## Why

- **Runs locally.** Queries go straight to the authoritative DNS, WHOIS and TLS
  endpoints (and [crt.sh](https://crt.sh) for subdomains). Nothing is sent to a
  domainintel.app server. Your lookups stay yours.
- **No install required.** `npx @domainintel/cli example.com`.
- **Zero runtime dependencies.** Ships as a single self-contained bundle.
- **Scriptable.** `--json` for piping to `jq`, meaningful exit codes for CI gates.

## Install

```bash
# one-off, no install
npx @domainintel/cli example.com

# or install globally for the `domainintel` command
npm install -g @domainintel/cli
domainintel example.com
```

Requires Node.js 18 or newer.

## Usage

```
domainintel <domain>              Full report (default)
domainintel <command> <domain>    Run a single check
```

### Commands

| Command       | What it checks |
|---------------|----------------|
| `full`        | Everything below, plus an overall A+–F security score (default) |
| `dns`         | A, AAAA, MX, TXT, NS, CNAME, CAA records + SPF/DMARC presence + misconfig warnings |
| `whois`       | Registrar, creation/expiry/updated dates, privacy status, registrant country |
| `ssl`         | TLS certificate: validity, issuer, expiry countdown, protocol, SANs |
| `headers`     | HTTP security headers (HSTS, CSP, X-Frame-Options, …) with a letter grade |
| `reputation`  | DNSBL and Spamhaus blocklist checks |
| `subdomains`  | Subdomain discovery via Certificate Transparency logs |

### Options

| Flag | Description |
|------|-------------|
| `--json` | Output raw JSON instead of the formatted report (pipeable to `jq`) |
| `-e`, `--exit-code` | Exit `1` if the check finds problems (for CI gates) |
| `--fail-under <days>` | *(ssl)* Exit `1` if the certificate expires within `<days>` |
| `--no-color` | Disable coloured output (also respects `NO_COLOR` and non-TTY pipes) |
| `--debug` | Show the underlying analyzer's debug logs on stderr |
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show version |

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Ran successfully; no problems (or `--exit-code` not set) |
| `1`  | Ran successfully but found problems (only when `--exit-code` is set) |
| `2`  | Could not run: bad usage, invalid domain, or an analysis failure |

## Examples

**Pipe JSON to jq:**

```bash
domainintel dns example.com --json | jq '.dns.mx'
domainintel ssl example.com --json | jq '.ssl.daysRemaining'
```

**Gate a deploy on certificate expiry:**

```bash
# fails the build if the cert expires within 14 days
domainintel ssl yourdomain.com --fail-under 14 --exit-code
```

**Fail if SPF/DMARC are misconfigured:**

```bash
domainintel dns yourdomain.com --exit-code
```

**Audit a fleet of domains:**

```bash
cat domains.txt | xargs -I{} domainintel whois {} --json > whois.ndjson
```

## Use in CI

### GitHub Action

This repo doubles as a GitHub Action, so you don't even need to script `npx`:

```yaml
name: domain-health
on:
  schedule:
    - cron: '0 6 * * *'   # daily
  workflow_dispatch:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - name: SSL not expiring within 21 days
        uses: Bishop81/domainintel-cli@v1
        with:
          domain: ${{ vars.DOMAIN }}
          check: ssl
          fail-under: 21
      - name: DNS / email auth configured
        uses: Bishop81/domainintel-cli@v1
        with:
          domain: ${{ vars.DOMAIN }}
          check: dns
```

Inputs: `domain` (required), `check` (default `full`), `fail-under` (ssl only), `exit-code` (default `true`, fail on problems), `json`.

### GitHub Actions (raw CLI)

Or call the CLI directly. Catch an expiring certificate before your users (or your monitoring) do:

```yaml
name: domain-health
on:
  schedule:
    - cron: '0 6 * * *'   # daily
  workflow_dispatch:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: SSL certificate not expiring within 21 days
        run: npx @domainintel/cli ssl ${{ vars.DOMAIN }} --fail-under 21 --exit-code
      - name: DNS / email auth configured
        run: npx @domainintel/cli dns ${{ vars.DOMAIN }} --exit-code
```

### GitLab CI

```yaml
domain-health:
  image: node:20
  script:
    - npx @domainintel/cli ssl "$DOMAIN" --fail-under 21 --exit-code
```

## JSON output

`--json` emits the same structure the [MCP server](https://www.npmjs.com/package/@domainintel/mcp)
returns. Single checks are wrapped under their key (`{ "domain": ..., "dns": {...} }`);
`full` returns the complete report including `securityScore`. Stdout stays clean even
for the noisier checks, so it's always safe to pipe.

## Related

- **[domainintel.app](https://domainintel.app)** — the full web dashboard with PDF export.
- **[@domainintel/mcp](https://www.npmjs.com/package/@domainintel/mcp)** — the same
  engine as a Model Context Protocol server, so AI agents (Claude, Cursor) can run
  these checks directly.
- **[Guides](https://domainintel.app/guides)** — explainers on DNS, SPF/DMARC, SSL,
  security headers and more.

## License

MIT
