require "option_parser"

module Shards::Audit
  class CLI
    EXIT_CLEAN = 0
    EXIT_VULNS = 1
    EXIT_ERROR = 2

    class_property stdout : IO = STDOUT

    # A single stderr sink. `CLI.stderr` and `Shards::Audit.stderr` used to
    # be independent class properties, so redirecting one still let scanner,
    # client and config diagnostics escape through the other — which is why
    # spec output kept leaking warnings to the real terminal.
    def self.stderr : IO
      Shards::Audit.stderr
    end

    def self.stderr=(io : IO) : IO
      Shards::Audit.stderr = io
    end

    def self.run(args = ARGV) : Int32
      config = Config.new
      config_path : String? = nil
      no_config = false

      show_help = false
      show_version = false

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: shards-audit [options]"
        opts.separator ""
        opts.separator "Scan Crystal shard dependencies for known vulnerabilities."
        opts.separator ""
        opts.separator "Options:"

        opts.on("-p PATH", "--path PATH", "Path to shard.lock (default: ./shard.lock)") do |path|
          raise ArgumentError.new("--path requires a non-empty value.") if path.blank?
          config.lockfile_path = path
        end

        opts.on("-f FORMAT", "--format FORMAT", "Output format: table, json, yaml, toml, sarif (default: table)") do |format|
          case format.downcase
          when "table"       then config.format = OutputFormat::Table
          when "json"        then config.format = OutputFormat::Json
          when "yaml", "yml" then config.format = OutputFormat::Yaml
          when "toml"        then config.format = OutputFormat::Toml
          when "sarif"       then config.format = OutputFormat::Sarif
          else
            raise ArgumentError.new("Unknown format: #{format}. Use 'table', 'json', 'yaml', 'toml', or 'sarif'.")
          end
        end

        opts.on("--github-token TOKEN", "GitHub API token (or set GITHUB_TOKEN env)") do |token|
          config.github_token = token
        end

        opts.on("--no-color", "Disable colored output") do
          config.no_color = true
        end

        opts.on("-v", "--verbose", "Show verbose output") do
          config.verbose = true
        end

        opts.on("--no-cache", "Disable response caching") do
          config.no_cache = true
        end

        opts.on("--cache-dir PATH", "Cache directory (default: ~/.cache/shards-audit/)") do |path|
          # An empty value made File.join produce a relative path, scattering
          # the cache through the working directory.
          raise ArgumentError.new("--cache-dir requires a non-empty value.") if path.blank?
          config.cache_dir = path
        end

        opts.on("--cache-ttl SECONDS", "Cache TTL in seconds (default: 86400)") do |seconds|
          value = seconds.to_i32? || raise ArgumentError.new("Invalid cache TTL: '#{seconds}'. Must be a positive integer.")
          raise ArgumentError.new("Cache TTL must be positive, got #{value}.") if value <= 0
          config.cache_ttl = value
        end

        opts.on("--timeout SECONDS", "HTTP request timeout in seconds (default: 30)") do |seconds|
          value = seconds.to_i32? || raise ArgumentError.new("Invalid timeout: '#{seconds}'. Must be a positive integer.")
          raise ArgumentError.new("Timeout must be positive, got #{value}.") if value <= 0
          config.timeout = value
        end

        opts.on("--ignore VULN_ID", "Ignore a specific vulnerability ID (repeatable)") do |id|
          config.ignore_ids << id
        end

        opts.on("--config PATH", "Path to .shards-audit.yml config file") do |path|
          config_path = path
        end

        opts.on("--no-config", "Disable config file loading") do
          no_config = true
        end

        opts.on("--severity-threshold LEVEL", "Only report vulnerabilities at or above this level (low/medium/high/critical)") do |level|
          threshold = Severity.from_string(level)
          if threshold.unknown?
            raise ArgumentError.new("Unknown severity level: #{level}. Use 'low', 'medium', 'high', or 'critical'.")
          end
          config.severity_threshold = threshold
        end

        opts.on("--exit-zero", "Always exit with 0 even if vulnerabilities are found") do
          config.exit_zero = true
        end

        opts.on("--version", "Show version") do
          show_version = true
        end

        opts.on("-h", "--help", "Show help") do
          show_help = true
        end
      end

      # Without an unknown_args handler OptionParser silently discards
      # leftover positionals, so `shards-audit path/to/shard.lock` scanned
      # ./shard.lock instead and a CI job got a green pass for a file it
      # never read.
      parser.unknown_args do |before_dash, _|
        unless before_dash.empty?
          raise ArgumentError.new(
            "Unexpected argument: #{before_dash.first.inspect}. Use '-p PATH' to choose a lockfile.")
        end
      end

      parser.parse(args)

      if show_version
        @@stdout.puts "shards-audit #{VERSION}"
        return EXIT_CLEAN
      end

      if show_help
        @@stdout.puts parser
        return EXIT_CLEAN
      end

      run_audit(config, config_path: config_path, no_config: no_config)
    rescue ex : OptionParser::InvalidOption | OptionParser::MissingOption | ArgumentError
      stderr.puts "Error: #{ex.message}"
      stderr.puts "Run 'shards-audit --help' for usage."
      EXIT_ERROR
    rescue ex : Exception
      # Anything unhandled must still exit 2. Letting it escape to `main`
      # aborts with status 1 — indistinguishable from EXIT_VULNS, so a
      # crashing audit reads to CI as a successful scan that found
      # vulnerabilities.
      stderr.puts "Error: unexpected failure: #{ex.message} (#{ex.class})"
      stderr.puts "Please report this at https://github.com/hahwul/shards-audit/issues"
      EXIT_ERROR
    end
  end
end
