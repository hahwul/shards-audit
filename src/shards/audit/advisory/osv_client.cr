require "json"

module Shards::Audit
  # Raised when OSV returns an unexpected response shape (e.g. a
  # querybatch reply whose results length does not match the request).
  # Refusing to silently misalign results is safer than reporting wrong
  # vulnerabilities for the wrong dependency.
  class OsvResponseError < Exception
  end

  class OsvClient
    include HttpRetry
    include HttpClient
    include OsvParser
    include OsvQueryBuilder
    include AdvisorySource

    OSV_API_BASE = "https://api.osv.dev"

    # Cap on follow-up pages per dependency. The current OSV API does not
    # publish a hard limit; stop after a generous bound to avoid runaway
    # loops if a backend regression returns the same page_token forever.
    MAX_OSV_PAGES = 16

    def initialize(@timeout : Int32 = 30, @verbose : Bool = false, @cache : Cache? = nil)
    end

    def query_batch(dependencies : Array(Dependency)) : Hash(String, Array(String))
      # Build queries paired with their dependency for accurate index mapping.
      # Primary: git URL based. Secondary: normalized GitHub URL (only when distinct).
      # Dependencies without commit or version are skipped (nil query).
      query_deps = [] of Dependency
      queries = [] of String

      dependencies.each do |dep|
        if q = build_osv_query(dep, normalize_git_url(dep.git_url))
          queries << q
          query_deps << dep
        end
      end

      dependencies.each do |dep|
        next unless dep.github_owner_repo
        if q = build_osv_query(dep, "https://github.com/#{dep.github_owner_repo}")
          queries << q
          query_deps << dep
        end
      end

      return Hash(String, Array(String)).new { |h, k| h[k] = [] of String } if queries.empty?

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
      vuln_ids_by_dep, followups = extract_vuln_ids_mapped(response, query_deps)

      # Resolve any per-result pagination so dependencies that exceeded the
      # querybatch page cap don't silently lose trailing vulnerabilities.
      # Follow-ups are tagged by query index so a dep that was queried via
      # both git URL and GitHub URL re-fires the correct one.
      followups.each do |idx, page_token|
        follow_paginated_query(query_deps[idx], queries[idx], page_token, vuln_ids_by_dep)
      end

      vuln_ids_by_dep
    end

    private def follow_paginated_query(dep : Dependency, query_body : String, page_token : String, vuln_ids_by_dep : Hash(String, Array(String)))
      token : String? = page_token
      pages = 0
      while token && pages < MAX_OSV_PAGES
        pages += 1
        body = JSON.build do |json|
          json.object do
            JSON.parse(query_body).as_h.each { |k, v| json.field k, v }
            json.field "page_token", token
          end
        end
        log("OSV follow-up page #{pages} for #{dep.name}")
        response = make_request("POST", "/v1/query", body)
        token = merge_query_response(response, dep, vuln_ids_by_dep)
      end

      log("OSV pagination cap (#{MAX_OSV_PAGES}) reached for #{dep.name}; trailing pages skipped") if token
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
      Shards::Audit.stderr.puts("[OSV] #{message}") if @verbose
    end
  end
end
