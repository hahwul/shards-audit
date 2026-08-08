module Shards::Audit
  class Scanner
    SOURCE_COUNT = 2

    def initialize(@config : Config)
      @dep_map = Hash(String, Dependency).new
    end

    alias ScanResult = {Array(Vulnerability), String?}

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

      osv_channel = Channel(ScanResult).new
      github_channel = Channel(ScanResult).new

      spawn do
        osv_channel.send(scan_osv(dependencies))
      end

      spawn do
        github_channel.send(scan_github(dependencies))
      end

      osv_vulns, osv_error = osv_channel.receive
      github_vulns, github_error = github_channel.receive

      result.errors << osv_error if osv_error
      result.errors << github_error if github_error

      all_vulns = deduplicate(osv_vulns + github_vulns)
      VulnerabilityFilter.new(@config, @dep_map).apply(all_vulns, result)

      elapsed = (Time.instant - start_time).total_milliseconds
      log("Total scan completed in #{elapsed.round(0)}ms")

      result
    end

    private def build_cache : Cache?
      return if @config.no_cache
      Cache.new(@config.cache_dir, @config.cache_ttl)
    end

    private def scan_osv(dependencies : Array(Dependency)) : ScanResult
      start = Time.instant
      client = OsvClient.new(timeout: @config.timeout, verbose: @config.verbose, cache: build_cache)
      vulns = client.scan(dependencies)
      elapsed = (Time.instant - start).total_milliseconds
      log("OSV scan: #{vulns.size} vulnerabilities found in #{elapsed.round(0)}ms")
      {vulns, nil}
    rescue ex : Exception
      {[] of Vulnerability, "OSV scan failed: #{ex.message}"}
    end

    private def scan_github(dependencies : Array(Dependency)) : ScanResult
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
      # A source that failed for every dependency is a failed source, even
      # though `scan` returned normally. Without this the CLI cannot tell
      # "GitHub found nothing" from "GitHub never answered".
      {vulns, client.errors.empty? ? nil : "GitHub scan: #{client.errors.join("; ")}"}
    rescue ex : Exception
      {[] of Vulnerability, "GitHub scan failed: #{ex.message}"}
    end

    # Collapses findings that the two sources reported for the same
    # dependency, then returns them in a stable, total order.
    def deduplicate(vulnerabilities : Array(Vulnerability)) : Array(Vulnerability)
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

      # Severity first, then a total tiebreak on (dependency, id). Crystal's
      # sort is not stable, so severity alone left equally-severe findings in
      # an arbitrary order that also depended on which source's fiber
      # finished first — meaning two runs over an unchanged shard.lock could
      # emit different JSON/SARIF and churn CI diffs.
      unique.sort_by { |v| {-v.severity.priority, v.dependency_name, v.id} }
    end

    private def log(message : String)
      Shards::Audit.stderr.puts("[Scanner] #{message}") if @config.verbose
    end
  end
end
