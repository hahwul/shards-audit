module Shards::Audit
  class Scanner
    def initialize(@config : Config)
      @dep_map = Hash(String, Dependency).new
    end

    def scan(dependencies : Array(Dependency)) : AuditResult
      result = AuditResult.new
      result.dependencies_scanned = dependencies.size

      if dependencies.empty?
        return result
      end

      # Build name→Dependency map for version lookup
      @dep_map = dependencies.each_with_object(Hash(String, Dependency).new) do |dep, map|
        map[dep.name] = dep
      end

      start_time = Time.instant

      osv_channel = Channel(Array(Vulnerability)).new
      github_channel = Channel(Array(Vulnerability)).new

      spawn do
        osv_channel.send(scan_osv(dependencies, result))
      end

      spawn do
        github_channel.send(scan_github(dependencies, result))
      end

      osv_vulns = osv_channel.receive
      github_vulns = github_channel.receive

      all_vulns = deduplicate(osv_vulns + github_vulns)
      VulnerabilityFilter.new(@config, @dep_map).apply(all_vulns, result)

      elapsed = (Time.instant - start_time).total_milliseconds
      log("Total scan completed in #{elapsed.round(0)}ms")

      result
    end

    private def build_cache : Cache?
      return nil if @config.no_cache
      Cache.new(@config.cache_dir, @config.cache_ttl)
    end

    private def scan_osv(dependencies : Array(Dependency), result : AuditResult) : Array(Vulnerability)
      start = Time.instant
      client = OsvClient.new(timeout: @config.timeout, verbose: @config.verbose, cache: build_cache)
      vulns = client.scan(dependencies)
      elapsed = (Time.instant - start).total_milliseconds
      log("OSV scan: #{vulns.size} vulnerabilities found in #{elapsed.round(0)}ms")
      vulns
    rescue ex : Exception
      result.errors << "OSV scan failed: #{ex.message}"
      [] of Vulnerability
    end

    private def scan_github(dependencies : Array(Dependency), result : AuditResult) : Array(Vulnerability)
      start = Time.instant
      client = GithubClient.new(
        token: @config.github_token,
        timeout: @config.timeout,
        verbose: @config.verbose,
        cache: build_cache
      )
      vulns = client.scan(dependencies)
      elapsed = (Time.instant - start).total_milliseconds
      log("GitHub scan: #{vulns.size} vulnerabilities found in #{elapsed.round(0)}ms")
      vulns
    rescue ex : Exception
      result.errors << "GitHub scan failed: #{ex.message}"
      [] of Vulnerability
    end

    private def deduplicate(vulnerabilities : Array(Vulnerability)) : Array(Vulnerability)
      seen_ids = Set(String).new
      unique = [] of Vulnerability

      vulnerabilities.each do |vuln|
        ids = vuln.all_ids
        dep_ids = ids.map { |id| "#{vuln.dependency_name}:#{id}" }

        # Skip if any of this vulnerability's IDs (scoped to dep) were already seen
        next if dep_ids.any? { |did| seen_ids.includes?(did) }

        dep_ids.each { |did| seen_ids << did }
        unique << vuln
      end

      # Sort by severity (critical first)
      unique.sort_by do |v|
        case v.severity
        when Severity::Critical then 0
        when Severity::High     then 1
        when Severity::Medium   then 2
        when Severity::Low      then 3
        else                         4
        end
      end
    end

    private def log(message : String)
      STDERR.puts("[Scanner] #{message}") if @config.verbose
    end
  end
end
