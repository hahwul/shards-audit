require "yaml"

module Shards::Audit
  class YamlFormatter
    def format(result : AuditResult, io : IO = STDOUT) : Nil
      data = {
        "tool_version"           => VERSION,
        "timestamp"              => Time.utc.to_rfc3339,
        "dependencies_scanned"   => result.dependencies_scanned,
        "vulnerabilities_found"  => result.vulnerabilities_found,
        "vulnerabilities"        => result.vulnerabilities.map { |vuln| format_vuln(vuln) },
        "version_filtered_count" => result.version_filtered_count,
        "ignored_count"          => result.ignored_count,
        "filtered_count"         => result.filtered_count,
        "errors"                 => result.errors,
      }
      data.to_yaml(io)
    end

    alias RangeHash = Hash(String, String? | Bool)
    alias VulnValue = String? | Float64 | Array(String) | Array(RangeHash)

    private def format_vuln(vuln : Vulnerability) : Hash(String, VulnValue)
      {
        "id"              => vuln.id,
        "aliases"         => vuln.aliases,
        "summary"         => vuln.summary,
        "severity"        => vuln.severity.label,
        "cvss_score"      => vuln.cvss_score,
        "fixed_version"   => vuln.fixed_version,
        "dependency_name" => vuln.dependency_name,
        "source"          => vuln.source,
        "url"             => vuln.url,
        "affected_ranges" => vuln.affected_ranges.map do |r|
          RangeHash{
            "introduced"           => r.introduced.try(&.to_s),
            "fixed"                => r.fixed.try(&.to_s),
            "introduced_exclusive" => r.introduced_exclusive,
            "fixed_inclusive"      => r.fixed_inclusive,
            "constraint"           => r.to_constraint,
          }
        end,
      } of String => VulnValue
    end
  end
end
