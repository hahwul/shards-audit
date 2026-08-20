# shards-audit

Security vulnerability scanner for Crystal shard dependencies. Checks your `shard.lock` against [OSV](https://osv.dev/) and, for shards hosted on GitHub, the [repository security advisories](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-repository-security-advisories) each project publishes.

## Installation

Add to your `shard.yml`:

```yaml
development_dependencies:
  shards-audit:
    github: hahwul/shards-audit
```

Or build from source:

```bash
git clone https://github.com/hahwul/shards-audit.git
cd shards-audit
shards install
crystal build src/run.cr -o shards-audit --release
```

## Usage

```bash
shards-audit
```

### Options

```
-p, --path PATH              Path to shard.lock (default: ./shard.lock)
-f, --format FORMAT          Output format: table, json, yaml, toml, sarif (default: table)
    --github-token TOKEN     GitHub API token (or set GITHUB_TOKEN env)
    --no-color               Disable colored output (also honours NO_COLOR;
                             color is off automatically when stdout is piped)
-v, --verbose                Show verbose output
    --no-cache               Disable response caching
    --cache-dir PATH         Cache directory (default: ~/.cache/shards-audit/)
    --cache-ttl SECONDS      Cache TTL in seconds (default: 86400)
    --timeout SECONDS        HTTP request timeout in seconds (default: 30)
    --ignore VULN_ID         Ignore a specific vulnerability ID (repeatable)
    --config PATH            Path to .shards-audit.yml config file
    --no-config              Disable config file loading
    --severity-threshold LEVEL  Only report at or above level (low/medium/high/critical)
    --exit-zero              Always exit with 0 even if vulnerabilities are found
    --version                Show version
-h, --help                   Show help
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found (or `--exit-zero`) |
| 1 | Vulnerabilities found |
| 2 | Error, including an audit that could not be completed |

"No vulnerabilities found" is a claim about every source, so a run where a
source never answered — a network failure, a rejected token, an exhausted
GitHub quota — exits 2 rather than 0, even when nothing was found. Pass
`--exit-zero` to opt out.

### Examples

```bash
# Scan with GitHub token for higher API rate limits
shards-audit --github-token $GITHUB_TOKEN

# JSON output for CI pipelines
shards-audit -f json --exit-zero

# SARIF output for GitHub Code Scanning
shards-audit -f sarif > results.sarif

# Ignore specific vulnerabilities
shards-audit --ignore GHSA-xxxx-yyyy-zzzz --ignore CVE-2024-1234

# Only report high and critical
shards-audit --severity-threshold high
```

## Configuration

Create `.shards-audit.yml` in your project root (or home directory):

```yaml
ignore:
  - id: GHSA-xxxx-yyyy-zzzz
    reason: "False positive for our usage"
    expires: "2025-12-31"

severity_threshold: medium
```

An ignore entry stays suppressed through the whole of its `expires` date and
becomes active again the next day.

## Proxies

Outbound requests honour the conventional proxy environment variables. HTTPS
targets are reached with a `CONNECT` tunnel, so TLS still terminates at the
advisory API rather than at the proxy.

```bash
export HTTPS_PROXY=http://proxy.internal:3128
export NO_PROXY=.internal.example        # comma-separated; '*' disables proxying
shards-audit
```

`https_proxy`/`HTTPS_PROXY` apply to HTTPS targets, `http_proxy`/`HTTP_PROXY`
to HTTP, and `all_proxy`/`ALL_PROXY` to either. Credentials may be embedded in
the URL (`http://user:pass@proxy:3128`).

## Development

```bash
shards install
crystal spec
```

## Contributing

1. Fork it (<https://github.com/hahwul/shards-audit/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
