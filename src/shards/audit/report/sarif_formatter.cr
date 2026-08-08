require "sarif"

module Shards::Audit
  class SarifFormatter
    # SARIF locations must point at the file the finding came from. This was
    # hardcoded to "shard.lock", so with `--path sub/project/shard.lock`
    # GitHub Code Scanning annotated a non-existent root file and dropped
    # the alerts.
    def initialize(@lockfile_path : String = "shard.lock")
    end

    def format(result : AuditResult, io : IO = STDOUT) : Nil
      log = Sarif::Builder.build do |b|
        b.run("shards-audit", VERSION) do |r|
          r.information_uri("https://github.com/hahwul/shards-audit")

          # Track rule ids already emitted so each advisory id produces only
          # one reportingDescriptor, even when it affects multiple
          # dependencies. SARIF 2.1.0 §3.49.3 requires rule ids to be unique
          # within driver.rules; duplicates break GitHub Code Scanning.
          emitted_rule_ids = Set(String).new
          location_uri = relative_location(@lockfile_path)

          result.vulnerabilities.each do |vuln|
            level = severity_to_level(vuln.severity)

            unless emitted_rule_ids.includes?(vuln.id)
              r.rule(vuln.id,
                name: vuln.id,
                short_description: vuln.summary.empty? ? vuln.id : vuln.summary,
                help_uri: vuln.url,
                level: level)
              emitted_rule_ids << vuln.id
            end

            message = build_message(vuln)

            r.result do |res|
              res.message(message)
                .rule_id(vuln.id)
                .level(level)
                .location(uri: location_uri)
                .fingerprint("vulnerabilityId", vuln.id)
                .partial_fingerprint("dependencyName", vuln.dependency_name)
            end
          end
        end
      end

      # The builder drops an empty results array, leaving a run with only a
      # `tool` key. GitHub Code Scanning treats `runs[].results[]` as
      # required, so a clean audit produced an upload it could reject — and
      # an upload with no results array is what *clears* previously reported
      # alerts. Without it, a vulnerability stays flagged after it is fixed.
      log.runs.each do |run|
        run.results ||= [] of Sarif::Result
      end

      io.puts log.to_pretty_json
    end

    # Code-scanning consumers resolve SARIF URIs against the repository
    # root, so emit a repo-relative path where we can derive one and never
    # leak an absolute build-machine path.
    private def relative_location(path : String) : String
      cleaned = path.lchop("./")
      return cleaned unless Path[cleaned].absolute?

      cwd = Dir.current
      expanded = File.expand_path(cleaned)
      if expanded.starts_with?(cwd + File::SEPARATOR)
        expanded[(cwd.size + 1)..]
      else
        File.basename(expanded)
      end
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
