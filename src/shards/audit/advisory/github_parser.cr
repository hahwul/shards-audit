require "json"

module Shards::Audit
  module GithubParser
    include JsonAccess
    include CvssParser

    # `owner_repo` is the shard's GitHub source; the advisories came from
    # that repository's endpoint.
    private def parse_advisories(body : String, dep_name : String, owner_repo : String? = nil) : Array(Vulnerability)
      data = JSON.parse(body)
      advisories = data.as_a? || return [] of Vulnerability

      advisories.compact_map do |advisory|
        ghsa_id = dig_s(advisory, "ghsa_id") || next
        next unless reportable?(advisory)

        summary = dig_s(advisory, "summary") || ""
        url = dig_s(advisory, "html_url")

        aliases = [] of String
        if cve_id = dig_s(advisory, "cve_id")
          aliases << cve_id
        end

        severity = Severity::Unknown
        cvss_score = nil

        # Prefer the pre-computed numeric score; fall back to scoring the
        # vector string ourselves when GitHub omits it. A missing score
        # appears as `null` *and* as a literal `0.0` alongside a real
        # vector, so treat a non-positive score as absent — otherwise a 9.8
        # critical was reported with `cvss_score: 0.0`.
        score = dig_f(advisory, "cvss", "score")
        score = nil if score && score <= 0.0
        score ||= dig_s(advisory, "cvss", "vector_string").try { |v| parse_cvss_score(v).try(&.[0]) }
        # A CVSS v4-only advisory leaves `cvss` null and publishes its score
        # only under `cvss_severities`, so the score was dropped.
        score ||= dig_f(advisory, "cvss_severities", "cvss_v4", "score").try { |v| v if v > 0.0 }
        if score
          cvss_score = score
          severity = Severity.from_cvss(score)
        end

        if severity.unknown?
          if sev_str = dig_s(advisory, "severity")
            severity = Severity.from_string(sev_str)
          end
        end

        fixed_version, affected_ranges = parse_advisory_vulnerabilities(advisory, dep_name, owner_repo)

        Vulnerability.new(
          id: ghsa_id,
          aliases: aliases,
          summary: summary,
          severity: severity,
          cvss_score: cvss_score,
          fixed_version: fixed_version,
          dependency_name: dep_name,
          source: "GitHub",
          url: url,
          affected_ranges: affected_ranges
        )
      end
    end

    # A retracted or not-yet-published advisory is not a finding.
    #
    # `withdrawn_at` marks an advisory GitHub has retracted; it was reported
    # like any other, so a retraction kept failing CI until someone added the
    # id to `ignore:` by hand. `state` appears on repository advisories: a
    # token with repository access also sees `draft` and `triage` entries,
    # which are unreviewed reports rather than confirmed vulnerabilities.
    private def reportable?(advisory : JSON::Any) : Bool
      return false if dig_s(advisory, "withdrawn_at").presence
      state = dig_s(advisory, "state").presence
      state.nil? || state == "published"
    end

    private def parse_advisory_vulnerabilities(advisory : JSON::Any, dep_name : String,
                                               owner_repo : String?) : {String?, Array(SemverRange)}
      fixed_version = nil
      affected_ranges = [] of SemverRange

      vulns = dig_a(advisory, "vulnerabilities") || return {fixed_version, affected_ranges}

      # A repository advisory can name several packages, and the names are
      # free-form (`kemal`, `kemalcr/kemal`, `crystal`). Judging the shard
      # against another package's range could both hide and invent a hit, so
      # only the entries naming this shard count. When none does, the repo
      # still returned the advisory, so keep every entry (conservative).
      applying = vulns.select { |vuln| package_applies?(dig_s(vuln, "package", "name"), dep_name, owner_repo) }
      vulns = applying unless applying.empty?

      # An entry whose range is null or unreadable affects versions we cannot
      # tell. Keeping only the other entries' windows judged the shard
      # unaffected whenever its own entry was that one, so the whole advisory
      # falls back to "assume affected", as OSV does for GIT-only entries.
      unfilterable = false
      vulns.each do |vuln|
        patched = extract_first_patched_version(vuln)
        fixed_version ||= patched
        ranges = SemverRangeParser.parse_github_range(dig_s(vuln, "vulnerable_version_range") || "", patched)
        unfilterable ||= ranges.empty?
        affected_ranges.concat(ranges)
      end

      {fixed_version, unfilterable ? [] of SemverRange : affected_ranges}
    end

    # An entry applies when it names no package, names the shard, or names
    # its source repository as `owner/repo`, optionally behind a host
    # (`github.com/owner/repo`, `https://github.com/owner/repo`).
    private def package_applies?(name : String?, dep_name : String, owner_repo : String?) : Bool
      name = name.try(&.strip.downcase).presence || return true
      return true if name == dep_name.downcase
      return false unless owner_repo
      segments = name.sub(%r{\A[a-z][a-z0-9+.-]*://}, "").chomp(".git").split('/', remove_empty: true)
      segments.shift if segments.size == 3
      segments.join('/') == owner_repo.downcase
    end

    # `first_patched_version` is a bare string in the GitHub REST advisory
    # schema but an object with an `identifier` field in the GraphQL schema
    # (and in some cached/mirrored payloads). Accept both rather than letting
    # the unexpected shape raise — an exception here used to kill the whole
    # GitHub source.
    #
    # Repository security advisories name the same thing `patched_versions`,
    # so reading only `first_patched_version` reported "no fix available" for
    # every advisory that came from that endpoint.
    private def extract_first_patched_version(vuln : JSON::Any) : String?
      if value = dig(vuln, "first_patched_version")
        patched = value.as_s?.try(&.scrub) || dig_s(value, "identifier")
        return patched if patched.presence
      end
      # Free text in that schema: maintainers write "none" when there is no
      # fix, which rendered as "Upgrade to >= none".
      dig_s(vuln, "patched_versions").presence.try { |v| v if v.matches?(/\d/) }
    end
  end
end
