require "json"

module Shards::Audit
  class OsvClient
    include HttpRetry
    include HttpClient
    include OsvParser
    include OsvQueryBuilder
    include AdvisorySource

    OSV_API_BASE = "https://api.osv.dev"

    def initialize(@timeout : Int32 = 30, @verbose : Bool = false, @cache : Cache? = nil)
    end

    def query_batch(dependencies : Array(Dependency)) : Hash(String, Array(String))
      # Build primary queries (git URL based) + secondary queries (normalized GitHub URL)
      # Only add a secondary query when it differs from the primary (i.e. dep has a GitHub owner/repo)
      queries = dependencies.map { |dep| build_osv_query(dep, normalize_git_url(dep.git_url)) }
      secondary_deps = dependencies.select(&.github_owner_repo)
      queries += secondary_deps.map { |dep|
        build_osv_query(dep, "https://github.com/#{dep.github_owner_repo}")
      }

      body = JSON.build do |json|
        json.object do
          json.field "queries" do
            json.array do
              queries.each do |q|
                json.raw(q)
              end
            end
          end
        end
      end

      log("OSV batch query for #{dependencies.size} dependencies (#{queries.size} queries)")

      response = make_request("POST", "/v1/querybatch", body)
      extract_vuln_ids(response, dependencies, secondary_deps)
    end

    def fetch_vulnerability(vuln_id : String) : Vulnerability?
      cache_key = "osv/vulns/#{vuln_id}.json"

      if cache = @cache
        if cached = cache.get(cache_key)
          log("Cache hit for #{vuln_id}")
          return parse_vulnerability(cached)
        end
      end

      log("Fetching OSV vulnerability: #{vuln_id}")
      response = make_request("GET", "/v1/vulns/#{vuln_id}")

      if cache = @cache
        cache.set(cache_key, response)
      end

      parse_vulnerability(response)
    rescue ex : IO::Error | Socket::ConnectError | JSON::ParseException
      log("Failed to fetch vulnerability #{vuln_id}: #{ex.message}")
      nil
    end

    MAX_CONCURRENCY = 10

    def scan(dependencies : Array(Dependency)) : Array(Vulnerability)
      return [] of Vulnerability if dependencies.empty?

      vuln_ids_by_dep = query_batch(dependencies)

      # Collect unique vuln IDs and map back to dependencies
      unique_vuln_ids = Set(String).new
      vuln_ids_by_dep.each_value { |ids| ids.each { |id| unique_vuln_ids << id } }
      return [] of Vulnerability if unique_vuln_ids.empty?

      # Fetch each unique vulnerability once in parallel
      fetched = Hash(String, Vulnerability?).new
      channel = Channel({String, Vulnerability?}).new(MAX_CONCURRENCY)

      unique_vuln_ids.each_slice(MAX_CONCURRENCY) do |batch|
        batch.each do |vuln_id|
          spawn do
            vuln = fetch_vulnerability(vuln_id)
            channel.send({vuln_id, vuln})
          end
        end

        batch.size.times do
          vid, vuln = channel.receive
          fetched[vid] = vuln
        end
      end

      # Build vulnerability list per dependency
      vulnerabilities = [] of Vulnerability
      vuln_ids_by_dep.each do |dep_name, vuln_ids|
        vuln_ids.each do |vid|
          next unless vuln = fetched[vid]?
          vulnerabilities << Vulnerability.new(
            id: vuln.id,
            aliases: vuln.aliases,
            summary: vuln.summary,
            severity: vuln.severity,
            cvss_score: vuln.cvss_score,
            fixed_version: vuln.fixed_version,
            dependency_name: dep_name,
            source: "OSV",
            url: vuln.url,
            affected_ranges: vuln.affected_ranges
          )
        end
      end

      vulnerabilities
    end

    private def make_request(method : String, path : String, body : String? = nil) : String
      with_retry do
        headers = HTTP::Headers{"Content-Type" => "application/json"}
        response = http_request(OSV_API_BASE, method, path, headers, body)

        if retryable_status?(response.status_code)
          raise IO::Error.new("OSV API returned #{response.status_code} (retryable)")
        end

        unless response.status.success?
          raise IO::Error.new("OSV API returned #{response.status_code}")
        end

        response.body
      end
    end

    private def log(message : String)
      STDERR.puts("[OSV] #{message}") if @verbose
    end
  end
end
