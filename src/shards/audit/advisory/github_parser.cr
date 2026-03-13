require "json"

module Shards::Audit
  module GithubParser
    private def parse_advisories(body : String, dep_name : String) : Array(Vulnerability)
      data = JSON.parse(body)
      advisories = data.as_a? || return [] of Vulnerability

      advisories.compact_map do |advisory|
        ghsa_id = advisory["ghsa_id"]?.try(&.as_s) || next
        summary = advisory["summary"]?.try(&.as_s) || ""
        url = advisory["html_url"]?.try(&.as_s)

        aliases = [] of String
        if cve_id = advisory["cve_id"]?.try(&.as_s)
          aliases << cve_id
        end

        severity = Severity::Unknown
        cvss_score = nil

        if cvss = advisory["cvss"]?
          if score = cvss["score"]?.try(&.as_f?)
            cvss_score = score
            severity = Severity.from_cvss(score)
          end
        end

        if severity.unknown?
          if sev_str = advisory["severity"]?.try(&.as_s)
            severity = Severity.from_string(sev_str)
          end
        end

        # Extract fixed version and affected ranges from vulnerabilities array
        fixed_version = nil
        affected_ranges = [] of SemverRange
        if vulns = advisory["vulnerabilities"]?.try(&.as_a)
          vulns.each do |vuln|
            if patched = vuln["first_patched_version"]?.try(&.["identifier"]?.try(&.as_s))
              fixed_version ||= patched
            end
            if range_str = vuln["vulnerable_version_range"]?.try(&.as_s)
              affected_ranges.concat(SemverRangeParser.parse_github_range(range_str))
            end
          end
        end

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
  end
end
