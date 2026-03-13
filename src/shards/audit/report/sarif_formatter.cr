require "sarif"

module Shards::Audit
  class SarifFormatter
    def format(result : AuditResult, io : IO = STDOUT) : Nil
      log = Sarif::Builder.build do |b|
        b.run("shards-audit", VERSION) do |r|
          r.information_uri("https://github.com/hahwul/shards-audit")

          result.vulnerabilities.each do |vuln|
            level = severity_to_level(vuln.severity)

            r.rule(vuln.id,
              name: vuln.id,
              short_description: vuln.summary.empty? ? vuln.id : vuln.summary,
              help_uri: vuln.url,
              level: level)

            message = build_message(vuln)

            r.result do |res|
              res.message(message)
                .rule_id(vuln.id)
                .level(level)
                .location(uri: "shard.lock")
                .fingerprint("vulnerabilityId", vuln.id)
                .partial_fingerprint("dependencyName", vuln.dependency_name)
            end
          end
        end
      end

      io.puts log.to_pretty_json
    end

    private def severity_to_level(severity : Severity) : Sarif::Level
      case severity
      when .critical?, .high? then Sarif::Level::Error
      when .medium?           then Sarif::Level::Warning
      else                         Sarif::Level::Note
      end
    end

    private def build_message(vuln : Vulnerability) : String
      parts = [] of String
      parts << "[#{vuln.severity.label}] #{vuln.id} in #{vuln.dependency_name}"
      parts << vuln.summary unless vuln.summary.empty?
      parts << "Aliases: #{vuln.aliases.join(", ")}" unless vuln.aliases.empty?
      if fixed = vuln.fixed_version
        parts << "Fix: upgrade to >= #{fixed}"
      end
      parts << "Source: #{vuln.source}"
      parts.join(" | ")
    end
  end
end
