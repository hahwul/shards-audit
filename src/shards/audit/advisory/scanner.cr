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

    # Overridable so integration specs can point the scanner at a local
    # stand-in for the advisory APIs. Constructing the clients inline left
    # the whole scan-to-report path untestable without real network calls.
    protected def build_osv_client : OsvClient
      OsvClient.new(timeout: @config.timeout, verbose: @config.verbose, cache: build_cache)
    end

    protected def build_github_client : GithubClient
      GithubClient.new(
        token: @config.github_token,
        timeout: @config.timeout,
        verbose: @config.verbose,
        cache: build_cache
      )
    end

    private def scan_osv(dependencies : Array(Dependency)) : ScanResult
      start = Time.instant
      client = build_osv_client
      vulns = client.scan(dependencies)
      elapsed = (Time.instant - start).total_milliseconds
      log("OSV scan: #{vulns.size} vulnerabilities found in #{elapsed.round(0)}ms")
      # Per-advisory lookup failures are swallowed so one bad payload cannot
      # kill the run, which also made a source that answered nothing look
      # like a source that found nothing. See GithubClient below.
      {vulns, client.errors.empty? ? nil : "OSV scan: #{client.errors.join("; ")}"}
    rescue ex : Exception
      {[] of Vulnerability, "OSV scan failed: #{ex.message}"}
    end

    private def scan_github(dependencies : Array(Dependency)) : ScanResult
      start = Time.instant
      client = build_github_client
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
      unique = [] of Vulnerability
      # dependency-scoped advisory id => index into `unique`
      positions = Hash(String, Int32).new

      vulnerabilities.each do |vuln|
        keys = vuln.all_ids.map { |id| "#{vuln.dependency_name}:#{id}" }
        existing = keys.each do |key|
          if index = positions[key]?
            break index
          end
        end

        if existing.is_a?(Int32)
          # Combine rather than drop. Discarding the later record threw away
          # whichever source happened to know the summary, the fix version or
          # the severity.
          unique[existing] = unique[existing].merge(vuln)
          # Merging can pull in new aliases, which must also resolve here.
          unique[existing].all_ids.each do |id|
            positions["#{unique[existing].dependency_name}:#{id}"] = existing
          end
        else
          unique << vuln
          keys.each { |key| positions[key] = unique.size - 1 }
        end
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
