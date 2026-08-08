module Shards::Audit
  class CLI
    private def self.load_config_file(config : Config, config_path : String?, no_config : Bool) : Nil
      return if no_config

      path = config_path || ConfigFile.find
      if path && File.exists?(path)
        begin
          cf = ConfigFile.load(path)
          @@stderr.puts "Loaded config: #{path}" if config.verbose

          # Merge ignore entries (active only)
          cf.ignore.each do |entry|
            if entry.active?
              config.ignore_ids << entry.id unless config.ignore_ids.includes?(entry.id)
            else
              @@stderr.puts "Warning: Ignore entry #{entry.id} has expired (#{entry.expires})" if config.verbose
            end
          end

          # severity_threshold: CLI flag takes priority
          if config.severity_threshold.nil? && cf.severity_threshold
            config.severity_threshold = cf.severity_threshold
          end
        rescue ex : YAML::ParseException | IO::Error
          @@stderr.puts "Warning: Failed to load config file #{path}: #{ex.message}"
        end
      elsif config_path
        @@stderr.puts "Warning: Config file not found: #{config_path}"
      end
    end

    private def self.run_audit(config : Config, config_path : String? = nil, no_config : Bool = false) : Int32
      load_config_file(config, config_path, no_config)

      # Parse lockfile
      parse_result = begin
        LockfileParser.parse(config.lockfile_path)
      rescue ex : LockfileParser::ParseError
        @@stderr.puts "Error: #{ex.message}"
        return EXIT_ERROR
      end

      dependencies = parse_result.dependencies

      if dependencies.empty?
        @@stdout.puts "No dependencies found in #{config.lockfile_path}."
        return EXIT_CLEAN
      end

      if config.verbose
        skipped = parse_result.skipped_deps
        unless skipped.empty?
          @@stderr.puts "Skipped #{skipped.size} non-git dependencies: #{skipped.join(", ")}"
        end
        @@stderr.puts "Scanning #{dependencies.size} dependencies..."
      end

      # Run scan
      scanner = Scanner.new(config)
      result = scanner.scan(dependencies)

      # Check if all sources failed
      if result.errors.size >= Scanner::SOURCE_COUNT && result.vulnerabilities.empty?
        @@stderr.puts "Error: All vulnerability sources failed."
        result.errors.each { |e| @@stderr.puts "  - #{e}" }
        @@stderr.puts
        @@stderr.puts "Suggestions:"
        @@stderr.puts "  - Check your network connection"
        @@stderr.puts "  - If behind a proxy, ensure HTTP_PROXY/HTTPS_PROXY are set"
        @@stderr.puts "  - Set --github-token or GITHUB_TOKEN for GitHub API access"
        @@stderr.puts "  - Run with --verbose for more details"
        return EXIT_ERROR
      end

      # Format output
      case config.format
      in OutputFormat::Table
        TableFormatter.new(no_color: config.no_color).format(result, @@stdout)
      in OutputFormat::Json
        JsonFormatter.new.format(result, @@stdout)
      in OutputFormat::Yaml
        YamlFormatter.new.format(result, @@stdout)
      in OutputFormat::Toml
        TomlFormatter.new.format(result, @@stdout)
      in OutputFormat::Sarif
        SarifFormatter.new(config.lockfile_path).format(result, @@stdout)
      end

      return EXIT_CLEAN if config.exit_zero
      result.clean? ? EXIT_CLEAN : EXIT_VULNS
    end
  end
end
