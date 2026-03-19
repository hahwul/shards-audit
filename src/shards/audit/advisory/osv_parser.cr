require "json"

module Shards::Audit
  module OsvParser
    include CvssParser

    private def extract_vuln_ids(body : String, dependencies : Array(Dependency), secondary_deps : Array(Dependency) = [] of Dependency) : Hash(String, Array(String))
      vuln_ids_by_dep = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
      data = JSON.parse(body)

      results = data["results"]?.try(&.as_a) || return vuln_ids_by_dep
      primary_count = dependencies.size

      results.each_with_index do |entry, idx|
        # Map index back to dependency (primary: 0..n-1, secondary: n..n+secondary_count-1)
        dep = if idx < primary_count
                dependencies[idx]
              else
                sec_idx = idx - primary_count
                next if sec_idx >= secondary_deps.size
                secondary_deps[sec_idx]
              end

        vulns = entry["vulns"]?.try(&.as_a) || next

        vulns.each do |vuln|
          if id = vuln["id"]?.try(&.as_s)
            vuln_ids_by_dep[dep.name] << id unless vuln_ids_by_dep[dep.name].includes?(id)
          end
        end
      end

      vuln_ids_by_dep
    end

    private def parse_vulnerability(body : String) : Vulnerability?
      data = JSON.parse(body)

      id = data["id"]?.try(&.as_s) || return nil
      summary = data["summary"]?.try(&.as_s) || ""
      aliases = data["aliases"]?.try(&.as_a.map(&.as_s)) || [] of String

      severity, cvss_score = extract_severity(data)
      fixed_version, all_semver_ranges = extract_affected_ranges(data)
      url = extract_advisory_url(data, id)

      Vulnerability.new(
        id: id,
        aliases: aliases,
        summary: summary,
        severity: severity,
        cvss_score: cvss_score,
        fixed_version: fixed_version,
        url: url,
        affected_ranges: all_semver_ranges,
      )
    end

    private def extract_severity(data : JSON::Any) : {Severity, Float64?}
      severity = Severity::Unknown
      cvss_score = nil

      # Try to get severity from CVSS
      if severity_arr = data["severity"]?.try(&.as_a)
        severity_arr.each do |sev|
          if score_str = sev["score"]?.try(&.as_s)
            if cvss = parse_cvss_score(score_str)
              cvss_score = cvss
              severity = Severity.from_cvss(cvss)
              break
            end
          end
        end
      end

      # Fallback to database_specific severity
      if severity.unknown?
        if db_severity = data["database_specific"]?.try(&.["severity"]?.try(&.as_s))
          severity = Severity.from_string(db_severity)
        end
      end

      {severity, cvss_score}
    end

    private def extract_affected_ranges(data : JSON::Any) : {String?, Array(SemverRange)}
      fixed_version = nil
      all_semver_ranges = [] of SemverRange

      if affected_arr = data["affected"]?.try(&.as_a)
        affected_arr.each do |affected|
          if ranges = affected["ranges"]?.try(&.as_a)
            ranges.each do |range|
              events = range["events"]?.try(&.as_a) || next
              # Extract fixed version from first match
              unless fixed_version
                events.each do |event|
                  if fixed = event["fixed"]?.try(&.as_s)
                    fixed_version = fixed
                    break
                  end
                end
              end
              # Parse semver ranges from events
              all_semver_ranges.concat(SemverRangeParser.parse_osv_events(events))
            end
          end
        end
      end

      {fixed_version, all_semver_ranges}
    end

    private def extract_advisory_url(data : JSON::Any, id : String) : String?
      url = nil.as(String?)

      if refs = data["references"]?.try(&.as_a)
        refs.each do |ref|
          ref_type = ref["type"]?.try(&.as_s)
          ref_url = ref["url"]?.try(&.as_s)
          if ref_url && (ref_type == "ADVISORY" || ref_type == "WEB")
            url = ref_url
            break
          end
        end
      end

      url || "https://osv.dev/vulnerability/#{id}"
    end
  end
end
