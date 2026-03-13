module Shards::Audit
  class TableFormatter
    RESET = "\e[0m"
    BOLD  = "\e[1m"
    DIM   = "\e[2m"

    def initialize(@no_color : Bool = false)
    end

    def format(result : AuditResult, io : IO = STDOUT) : Nil
      if result.clean?
        io.puts colorize("No vulnerabilities found!", "\e[32m") # green
        io.puts "#{result.dependencies_scanned} dependencies scanned."
        print_errors(result, io)
        return
      end

      io.puts
      io.puts colorize("#{result.vulnerabilities_found} vulnerabilities found!", "\e[31m")
      io.puts

      result.vulnerabilities.each_with_index do |vuln, idx|
        print_vulnerability(vuln, io)
        io.puts if idx < result.vulnerabilities.size - 1
      end

      io.puts
      summary = "#{result.dependencies_scanned} dependencies scanned, #{result.vulnerabilities_found} vulnerabilities found."
      extras = [] of String
      extras << "#{result.version_filtered_count} not affected" if result.version_filtered_count > 0
      extras << "#{result.ignored_count} ignored" if result.ignored_count > 0
      extras << "#{result.filtered_count} below threshold" if result.filtered_count > 0
      summary += " (#{extras.join(", ")})" unless extras.empty?
      io.puts summary
      print_errors(result, io)
    end

    private def print_vulnerability(vuln : Vulnerability, io : IO)
      # Severity with CVSS score: "HIGH (7.5) GHSA-xxxx"
      score_str = vuln.cvss_score ? " (#{vuln.cvss_score})" : ""
      severity_str = colorize("#{vuln.severity.label}#{score_str}", vuln.severity.color_code)
      io.puts "#{colorize("┌", DIM)} #{severity_str} #{colorize(vuln.id, BOLD)}"
      io.puts "#{colorize("│", DIM)} #{field("Package")}#{vuln.dependency_name}"
      io.puts "#{colorize("│", DIM)} #{field("Summary")}#{vuln.summary}" unless vuln.summary.empty?
      if fixed = vuln.fixed_version
        io.puts "#{colorize("│", DIM)} #{field("Fix")}Upgrade to >= #{fixed}"
      end
      if url = vuln.url
        io.puts "#{colorize("│", DIM)} #{field("URL")}#{url}"
      end
      io.puts "#{colorize("│", DIM)} #{field("Source")}#{vuln.source}"
      unless vuln.aliases.empty?
        io.puts "#{colorize("│", DIM)} #{field("Aliases")}#{vuln.aliases.join(", ")}"
      end
      io.puts "#{colorize("└", DIM)}"
    end

    private def field(name : String) : String
      colorize("#{name}:".ljust(10), BOLD)
    end

    private def print_errors(result : AuditResult, io : IO)
      return if result.errors.empty?
      io.puts
      result.errors.each do |err|
        io.puts colorize("Warning: #{err}", "\e[33m") # yellow
      end
    end

    private def colorize(text : String, code : String) : String
      return text if @no_color
      "#{code}#{text}#{RESET}"
    end
  end
end
