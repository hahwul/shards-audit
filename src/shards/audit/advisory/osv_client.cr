require "json"

module Shards::Audit
  # Raised when OSV returns an unexpected response shape (e.g. a
  # querybatch reply whose results length does not match the request).
  # Refusing to silently misalign results is safer than reporting wrong
  # vulnerabilities for the wrong dependency.
  class OsvResponseError < Exception
  end

  # Raised when a single `/v1/vulns/{id}` lookup could not be completed.
  # `fetch_vulnerability` used to answer nil for both "the request failed"
  # and "there is nothing to report", so a source that never answered was
  # indistinguishable from a clean scan.
  class OsvLookupError < Exception
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

    # OSV documents a 1000-query ceiling per querybatch request. Stay well
    # under it so a large lockfile is split rather than rejected wholesale.
    MAX_BATCH_QUERIES = 500

    def initialize(@timeout : Int32 = 30, @verbose : Bool = false, @cache : Cache? = nil,
                   @api_base : String = OSV_API_BASE)
    end

    def query_batch(dependencies : Array(Dependency)) : Hash(String, Array(String))
      # Build queries paired with their dependency for accurate index mapping.
      # Primary: git URL based. Secondary: normalized GitHub URL (only when distinct).
      # Dependencies without commit or version are skipped (nil query).
      query_deps = [] of Dependency
      queries = [] of String

      dependencies.each do |dep|
        build_dep_queries(dep).each do |q|
          queries << q
          query_deps << dep
        end
      end

      vuln_ids_by_dep = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
      return vuln_ids_by_dep if queries.empty?

      log("OSV batch query for #{dependencies.size} dependencies (#{queries.size} queries)")

      # OSV caps a querybatch at 1000 queries. Sending one unbounded POST
      # meant a large lockfile silently exceeded the cap and failed the whole
      # source — and since a dependency can now contribute up to three
      # queries, that ceiling arrives sooner than the dependency count
      # suggests.
      (0...queries.size).step(MAX_BATCH_QUERIES) do |offset|
        chunk_queries = queries[offset, MAX_BATCH_QUERIES]
        chunk_deps = query_deps[offset, MAX_BATCH_QUERIES]
        query_chunk(chunk_queries, chunk_deps, vuln_ids_by_dep)
      end

      vuln_ids_by_dep
    end

    private def query_chunk(queries : Array(String), query_deps : Array(Dependency), vuln_ids_by_dep : Hash(String, Array(String))) : Nil
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

      response = make_request("POST", "/v1/querybatch", body)
      followups = merge_batch_response(response, query_deps, vuln_ids_by_dep)

      # Resolve any per-result pagination so dependencies that exceeded the
      # querybatch page cap don't silently lose trailing vulnerabilities.
      # Follow-ups are tagged by query index so a dep queried through several
      # variants re-fires the correct one.
      followups.each do |idx, page_token|
        follow_paginated_query(query_deps[idx], queries[idx], page_token, vuln_ids_by_dep)
      end
    end

    # Queries to issue for one dependency, de-duplicated.
    #
    # Two problems this replaces. First, a commit query ignores the package
    # URL entirely, so building "git URL" and "GitHub URL" variants for a
    # dependency that has a commit produced the *same* JSON twice — every
    # such dep doubled its share of the request payload for nothing.
    # Second, `build_osv_query` returns a commit query *instead of* a
    # version query when both are present, but shard.lock normally records
    # both and OSV only matches a commit it has actually indexed. Advisories
    # recorded against a version range were therefore missed for any
    # dependency that happened to also carry a commit.
    private def build_dep_queries(dep : Dependency) : Array(String)
      package_urls = [normalize_git_url(dep.git_url)]
      if owner_repo = dep.github_owner_repo
        package_urls << "https://github.com/#{owner_repo}"
      end

      queries = [] of String
      if commit = dep.commit.presence
        queries << build_commit_query(commit)
      end

      if version = dep.version.presence
        package_urls.each do |url|
          queries << build_version_query(url, version)
        end
      end

      queries.uniq
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
    rescue ex : IO::Error | Socket::ConnectError | JSON::ParseException | TypeCastError | AdvisoryRequestError
      log("Failed to fetch vulnerability #{vuln_id}: #{ex.message}")
      raise OsvLookupError.new("#{vuln_id}: #{ex.message || ex.class.name}")
    end

    MAX_CONCURRENCY = 10

    # Distinct failure reasons seen during the last `scan`. Mirrors
    # `GithubClient#errors`; see the note there.
    getter errors : Array(String) = [] of String

    def scan(dependencies : Array(Dependency)) : Array(Vulnerability)
      @errors.clear
      return [] of Vulnerability if dependencies.empty?

      vuln_ids_by_dep = query_batch(dependencies)

      # Collect unique vuln IDs and map back to dependencies
      unique_vuln_ids = Set(String).new
      vuln_ids_by_dep.each_value { |ids| ids.each { |id| unique_vuln_ids << id } }
      return [] of Vulnerability if unique_vuln_ids.empty?

      # Fetch each unique vulnerability once in parallel
      fetched = Hash(String, Vulnerability?).new
      failures = 0
      channel = Channel({String, Vulnerability?, String?}).new(MAX_CONCURRENCY)

      unique_vuln_ids.each_slice(MAX_CONCURRENCY) do |batch|
        batch.each do |vuln_id|
          spawn do
            # See GithubClient#scan: a fiber that raises before sending
            # leaves `channel.receive` waiting forever, so guarantee a send.
            vuln = nil
            failure : String? = nil
            begin
              vuln = fetch_vulnerability(vuln_id)
            rescue ex : Exception
              failure = ex.message || ex.class.name
              log("Failed to fetch vulnerability #{vuln_id}: #{failure}")
            ensure
              channel.send({vuln_id, vuln, failure})
            end
          end
        end

        batch.size.times do
          vid, vuln, failure = channel.receive
          fetched[vid] = vuln
          if failure
            failures += 1
            @errors << failure unless @errors.includes?(failure)
          end
        end
      end

      # The batch query already told us these advisories exist; losing their
      # details is missing findings, not a clean result. Reporting nothing
      # and no error is how a transient OSV outage printed "No
      # vulnerabilities found!" and exited 0.
      if failures > 0
        @errors.unshift("#{failures} of #{unique_vuln_ids.size} OSV advisory lookups failed")
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
            affected_ranges: vuln.affected_ranges,
            affected_versions: vuln.affected_versions
          )
        end
      end

      vulnerabilities
    end

    private def make_request(method : String, path : String, body : String? = nil) : String
      with_retry do
        headers = HTTP::Headers{"Content-Type" => "application/json"}
        response = http_request(@api_base, method, path, headers, body)

        if retryable_status?(response.status_code)
          raise RetryableResponseError.new(
            "OSV API returned #{response.status_code} (retryable)",
            retry_after_seconds(response.headers["Retry-After"]?))
        end

        unless response.status.success?
          # Not an IO::Error: a 400 or 404 will answer the same way however
          # many times we ask, so retrying only adds latency.
          raise AdvisoryRequestError.new("OSV API returned #{response.status_code}")
        end

        response.body
      end
    end

    private def log(message : String)
      Shards::Audit.stderr.puts("[OSV] #{message}") if @verbose
    end
  end
end
