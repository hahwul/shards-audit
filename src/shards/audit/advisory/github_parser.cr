require "json"

module Shards::Audit
  module GithubParser
    include JsonAccess
    include CvssParser

    private def parse_advisories(body : String, dep_name : String) : Array(Vulnerability)
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
        if score
          cvss_score = score
          severity = Severity.from_cvss(score)
        end

        if severity.unknown?
          if sev_str = dig_s(advisory, "severity")
            severity = Severity.from_string(sev_str)
          end
        end

        fixed_version, affected_ranges = parse_advisory_vulnerabilities(advisory)

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

    private def parse_advisory_vulnerabilities(advisory : JSON::Any) : {String?, Array(SemverRange)}
      fixed_version = nil
      affected_ranges = [] of SemverRange

      vulns = dig_a(advisory, "vulnerabilities") || return {fixed_version, affected_ranges}

      vulns.each do |vuln|
        fixed_version ||= extract_first_patched_version(vuln)
        if range_str = dig_s(vuln, "vulnerable_version_range")
          affected_ranges.concat(SemverRangeParser.parse_github_range(range_str))
        end
      end

      {fixed_version, affected_ranges}
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
      dig_s(vuln, "patched_versions").presence
    end
  end
end
