require "json"

module Shards::Audit
  class JsonFormatter
    def format(result : AuditResult, io : IO = STDOUT) : Nil
      JSON.build(io, indent: 2) do |json|
        json.object do
          json.field "tool_version", VERSION
          json.field "timestamp", Time.utc.to_rfc3339
          json.field "dependencies_scanned", result.dependencies_scanned
          json.field "vulnerabilities_found", result.vulnerabilities_found
          json.field "vulnerabilities" do
            json.array do
              result.vulnerabilities.each do |vuln|
                json.object do
                  json.field "id", vuln.id
                  json.field "aliases", vuln.aliases
                  json.field "summary", vuln.summary
                  json.field "severity", vuln.severity.label
                  json.field "cvss_score", vuln.cvss_score
                  json.field "fixed_version", vuln.fixed_version
                  json.field "dependency_name", vuln.dependency_name
                  json.field "source", vuln.source
                  json.field "url", vuln.url
                  json.field "affected_ranges" do
                    json.array do
                      vuln.affected_ranges.each do |range|
                        json.object do
                          json.field "introduced", range.introduced.try(&.to_s)
                          json.field "fixed", range.fixed.try(&.to_s)
                        end
                      end
                    end
                  end
                end
              end
            end
          end
          json.field "version_filtered_count", result.version_filtered_count
          json.field "ignored_count", result.ignored_count
          json.field "filtered_count", result.filtered_count
          json.field "errors", result.errors
        end
      end
      io.puts
    end
  end
end
