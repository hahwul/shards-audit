# Changelog

## Unreleased

### Fixed

- **GitHub repositories whose name contains a dot were addressed incorrectly.**
  The owner/repo pattern stopped at the first dot, so `hahwul/sarif.cr` became
  `hahwul/sarif`. Since the `.cr` suffix is the dominant Crystal shard naming
  convention, advisory lookups silently targeted the wrong repository for a
  large share of real dependencies.
- **Malformed advisory JSON could deadlock the whole scan.** `null` and
  wrong-typed fields (GitHub's `cve_id: null`, `vulnerabilities: null`, a
  string `first_patched_version`; OSV's `summary: null`, a scalar
  `database_specific`) raised inside a scanning fiber. The fiber died before
  sending on its channel and the matching receive blocked forever.
- **OSV `GIT` ranges were compared as SemVer.** Their events hold commit
  hashes, which parse to nil bounds, and a nil-bounded range matches every
  version — so version filtering silently became a no-op and the suggested fix
  could be printed as "upgrade to >= 8b1a9953…".
- **CVSS scoring was an ad-hoc weight sum.** It has been replaced with the
  exact CVSS v3.0/v3.1 base-score formula. CVSS v4.0 vectors are no longer
  mis-scored as MEDIUM (the old heuristic ignored `VC`/`VI`/`VA`, which could
  hide a 9.8 critical behind `--severity-threshold high`); they are left
  unscored so the feed's own severity applies.
- **A broken lockfile exited 1 instead of 2.** Invalid YAML, a non-mapping
  root, a scalar shard entry, or a non-string `git` value escaped as an
  unhandled exception — and exit 1 means "vulnerabilities found", so CI read a
  crash as a completed audit. All input errors now raise `ParseError`, and
  `CLI.run` has a catch-all that exits 2.
- **An exhausted GitHub rate limit was retried.** A 403 was signalled as
  `IO::Error`, which the retry helper catches, so every dependency retried
  three times with backoff against a quota already known to be spent. Rate
  limits, bad credentials, and other non-recoverable statuses are now
  non-retryable, and once the quota is gone the remaining dependencies stop
  querying. The error message reports when the quota resets.
- **Report ordering was non-deterministic.** Sorting by severity alone with an
  unstable sort left equally-severe findings ordered by whichever source's
  fiber finished first, so an unchanged `shard.lock` could emit different
  JSON/SARIF between runs.
- **SARIF hardcoded `shard.lock` as the result location**, so `--path` pointing
  elsewhere made GitHub Code Scanning annotate a non-existent file.
- **Reports lost range-bound inclusivity.** An inclusive upper bound (OSV
  `last_affected`) was indistinguishable from an exclusive one; JSON/YAML/TOML
  now emit `introduced_exclusive`, `fixed_inclusive`, and a rendered
  `constraint`.
- **TOML output could be invalid**, because only `\n` was escaped and TOML
  forbids unescaped control characters such as `\r`.
- **`Semver.parse` rejected build metadata** (`1.2.3+git.abc`), and an
  unparseable bound degraded to "no bound". It also accepted `vvv1.0.0` by
  stripping every leading `v`.
- **Ignore entries expired a day early**, lapsing at 00:00 on the `expires`
  date rather than at the end of it.
- **OSV queries were duplicated and incomplete.** A commit query ignores the
  package URL, so the two package-URL variants emitted byte-identical JSON;
  and a commit query replaced the version query, missing advisories recorded
  against a version range.
- **A non-https advisory reference discarded the URL entirely** instead of
  falling back to the canonical OSV link.
- **A source that failed for every dependency was reported as a clean scan.**
  Per-dependency failures were swallowed so one bad payload could not kill the
  run, but that made a total failure indistinguishable from "found nothing" —
  an expired `GITHUB_TOKEN` or a spent quota printed "No vulnerabilities
  found!" and exited 0. Failure reasons now reach `AuditResult#errors`.
- **A 404 was cached as "no advisories" for the full 24h TTL.** 404 is also
  what GitHub returns during an outage or for a masked resource, so a
  transient failure poisoned that repository's result for a day. Only a real
  200 is persisted now.
- **`ALL_PROXY=socks5://…` broke every request.** Only HTTP CONNECT is
  implemented, and aiming it at a SOCKS listener does not fail fast — it hangs
  until the read timeout, which is retryable, so each dependency burned four
  full timeouts. Unsupported proxy schemes are ignored, falling back to a
  direct connection.
- **`NO_PROXY` did not match an unbracketed IPv6 entry.** `::1` was split into
  host `:` and port `1` by the port heuristic, so the traffic silently went
  through the proxy anyway.
- **A lockfile `git:` URL could smuggle query parameters into the advisory
  request.** The owner/repo character class is now restricted to what GitHub
  permits, and the value is URL-encoded at the call site.
- **An advisory mixing GIT and other-ecosystem entries could be filtered
  away.** OSV is queried with `ecosystem: "GIT"`, so the GIT entry is often the
  one that matched; judging our version against a different package's
  ecosystem range discarded real findings. Such advisories are no longer
  version-filtered.
- **A non-SemVer fixed version was dropped**, reporting "no fix available" for
  advisories that named one (`1.2.3.4`, `2.0.0.RELEASE`).
- **GitHub's `"score": 0.0` suppressed the vector computation**, reporting a
  9.8 critical with `cvss_score: 0.0`.
- **Deduplication discarded the richer of two reports.** OSV results are
  concatenated ahead of GitHub's and the first record won, so a sparse OSV
  entry threw away GitHub's severity, summary, CVSS score and fix version for
  the same GHSA — the finding was displayed as UNKNOWN with no description and
  no remediation. Duplicates are now merged field by field, severity is
  resolved toward the higher rating so combining sources can never downgrade a
  finding, and the report names both sources.
- **A multi-window GitHub version range collapsed to its last window.**
  `">= 1.0.0, < 1.1.0, >= 2.0.0, < 2.1.0"` kept only `>= 2.0.0, < 2.1.0`, so a
  user on 1.0.5 — squarely inside the first window — was reported as not
  affected. A false negative, the failure mode the tool exists to prevent.
- **Constraints written without a space were dropped.** `">=1.0.0, <1.2.0"`
  parsed to no ranges at all, disabling version filtering for that advisory.
  A bare version with no operator is now read as an exact match.
- **The OSV querybatch was never chunked.** OSV caps a request at 1000
  queries, so a large lockfile silently exceeded the cap and failed the whole
  source. Queries are now split into batches of 500.

### Changed

- Colour output now defaults to the environment: it is disabled when
  `NO_COLOR` is set or when stdout is not a terminal, so piping the table into
  a file or a CI log no longer captures escape sequences. `--no-color` still
  forces it off.
- The cache directory honours `XDG_CACHE_HOME` before falling back to
  `~/.cache/shards-audit`.

### Added

- HTTP(S) proxy support via `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` with
  `NO_PROXY` exclusions, using `CONNECT` tunnelling so TLS terminates at the
  advisory API. The "all sources failed" hint already told users to set these
  variables, but nothing read them.

## v0.1.0

- Initial release
