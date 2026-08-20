require "json"

module Shards::Audit
  class GithubClient
    include HttpRetry
    include HttpClient
    include GithubParser
    include AdvisorySource

    GITHUB_API_BASE = "https://api.github.com"

    @token : String?

    def initialize(token : String? = nil, @timeout : Int32 = 30, @verbose : Bool = false, @cache : Cache? = nil,
                   @api_base : String = GITHUB_API_BASE)
      # A blank token is no token. `--github-token ""` sent `Authorization:
      # Bearer ` and got every request rejected with 401, and `sanitize_log`
      # redacted the empty string — which `String#gsub` matches between every
      # character, turning each log line into a wall of `[REDACTED]`.
      @token = token.presence

      # Set once the API tells us the quota is gone. Every later dependency
      # would get the same answer, so stop asking instead of walking the
      # whole lockfile against a limit we already know is exhausted.
      @rate_limited = false
    end

    private def rate_limited?(response : HTTP::Client::Response) : Bool
      return true if response.headers["x-ratelimit-remaining"]? == "0"
      body = response.body
      body.includes?("rate limit") || body.includes?("secondary rate")
    end

    private def rate_limit_message(response : HTTP::Client::Response) : String
      hint = @token ? "quota resets at" : "use --github-token for higher limits; quota resets at"
      reset = response.headers["x-ratelimit-reset"]?.try(&.to_i64?)
      if reset
        "GitHub API rate limit exceeded (#{hint} #{Time.unix(reset).to_rfc3339})"
      else
        "GitHub API rate limit exceeded (#{@token ? "authenticated quota" : "use --github-token for higher limits"})"
      end
    end

    MAX_CONCURRENCY = 5

    # Distinct failure reasons seen during the last `scan`.
    #
    # Swallowing per-dependency failures keeps one bad payload from killing
    # the run, but it also made a *total* source failure indistinguishable
    # from a clean result: an expired GITHUB_TOKEN or a spent quota meant
    # every dependency failed, `scan` still returned an empty array, and the
    # CLI printed "No vulnerabilities found!" and exited 0. Surfacing the
    # reasons lets the scanner report them and the "all sources failed"
    # check actually fire.
    getter errors : Array(String) = [] of String

    def scan(dependencies : Array(Dependency)) : Array(Vulnerability)
      @errors.clear
      github_deps = dependencies.select(&.github?)
      return [] of Vulnerability if github_deps.empty?

      vulnerabilities = [] of Vulnerability
      failures = 0
      channel = Channel({Array(Vulnerability), String?}).new(MAX_CONCURRENCY)

      github_deps.each_slice(MAX_CONCURRENCY) do |batch|
        batch.each do |dep|
          spawn do
            # Every path must reach `channel.send`. An exception escaping a
            # fiber does not propagate to the caller: the fiber just dies,
            # the matching `channel.receive` below blocks forever and the
            # whole process deadlocks. So catch Exception, not a hand-picked
            # list — a malformed advisory payload must cost us one
            # dependency, never the scan.
            vulns = [] of Vulnerability
            failure : String? = nil
            begin
              if owner_repo = dep.github_owner_repo
                vulns = query_advisories(owner_repo, dep.name)
              end
            rescue ex : Exception
              failure = ex.message || ex.class.name
              log("Failed to query advisories for #{dep.name}: #{failure}")
            ensure
              channel.send({vulns, failure})
            end
          end
        end

        batch.size.times do
          vulns, failure = channel.receive
          vulnerabilities.concat(vulns)
          if failure
            failures += 1
            @errors << failure unless @errors.includes?(failure)
          end
        end
      end

      if failures == github_deps.size && !github_deps.empty?
        @errors.unshift("all #{failures} GitHub lookups failed")
      end

      vulnerabilities
    end

    MAX_PAGES = 10

    private def query_advisories(owner_repo : String, dep_name : String) : Array(Vulnerability)
      # Namespaced by endpoint. The previous key held the *global* advisory
      # database's answer, which is an empty list for every Crystal shard —
      # reusing it would serve "no advisories" from disk for the whole TTL
      # after this upgrade.
      cache_key = "github/repo-advisories/#{owner_repo}.json"

      if cache = @cache
        if cached = cache.get(cache_key)
          log("Cache hit for #{owner_repo}")
          return parse_advisories(cached, dep_name)
        end
      end

      # Cached entries are still served above; only new requests stop.
      raise AdvisoryRequestError.new("GitHub API rate limit exceeded") if @rate_limited

      log("Querying GitHub advisories for #{owner_repo}")

      collected = [] of JSON::Any
      cacheable = true
      path : String? = advisories_path(owner_repo)
      page = 0

      while path && page < MAX_PAGES
        page += 1
        body, next_path, ok = make_request_with_links("GET", path)
        cacheable &&= ok

        if items = JSON.parse(body).as_a?
          collected.concat(items)
        end

        path = next_path
        log("Following pagination page #{page + 1} for #{owner_repo}") if path
      end

      all_advisories = collected.to_json

      # Only a real 200 is worth persisting. A 404/422 is synthesised into an
      # empty list so the scan can continue, but writing that to disk pinned
      # "this repository has no advisories" for the whole 24h TTL — and 404
      # is also what GitHub returns during an outage or for a temporarily
      # masked resource.
      if (cache = @cache) && cacheable
        cache.set(cache_key, all_advisories)
      end

      parse_advisories(all_advisories, dep_name)
    end

    # Where a Crystal shard's advisories actually live.
    #
    # The source used to query the *global* advisory database with
    # `/advisories?affects=owner/repo`. `affects` filters by package name
    # inside a GitHub-supported ecosystem, and Crystal is not one of them —
    # so the query returned `[]` for every shard, and the GitHub source
    # could never contribute a single finding. Confirmed against the live
    # API: `GET /advisories?affects=hahwul/sarif.cr` answers `[]`, and
    # GHSA-wqh5-7w63-pm68 (a published Crystal advisory) is not in the global
    # database at all — `GET /advisories/GHSA-wqh5-7w63-pm68` is a 404.
    #
    # Repository security advisories are where a shard maintainer publishes,
    # and the endpoint serves published ones without authentication.
    #
    # `state=published` matters once a token is supplied: a collaborator's
    # token also sees draft and triage advisories, which are unconfirmed and
    # must not be reported as findings.
    private def advisories_path(owner_repo : String) : String
      owner, _, repo = owner_repo.partition('/')
      # Encoded even though GITHUB_URL_PATTERN already restricts the charset
      # — the value originates in the lockfile, so the request path should
      # not depend on the regex staying tight.
      "/repos/#{URI.encode_path_segment(owner)}/#{URI.encode_path_segment(repo)}" \
      "/security-advisories?per_page=100&state=published"
    end

    # Returns {body, next_page_path, came_from_a_200}.
    private def make_request_with_links(method : String, path : String) : {String, String?, Bool}
      with_retry do
        headers = HTTP::Headers{
          "Accept"               => "application/vnd.github+json",
          "X-GitHub-Api-Version" => "2022-11-28",
          "User-Agent"           => "shards-audit/#{VERSION}",
        }

        if token = @token
          headers["Authorization"] = "Bearer #{token}"
        end

        response = http_request(@api_base, method, path, headers)

        # A 429 whose quota counter has already reached zero is the primary
        # rate limit, which no amount of retrying reopens — it is the same
        # condition the 403 branch below latches on, and it was being retried
        # three times per dependency with backoff.
        if response.status_code == 429 && response.headers["x-ratelimit-remaining"]? == "0"
          @rate_limited = true
          raise AdvisoryRequestError.new(rate_limit_message(response))
        end

        if retryable_status?(response.status_code)
          raise RetryableResponseError.new(
            "GitHub API returned #{response.status_code} (retryable)",
            retry_after_seconds(response.headers["Retry-After"]?))
        end

        case response.status_code
        when 200
          next_link = parse_next_link(response.headers["Link"]?) if response.headers["Link"]?
          {response.body, next_link, true}
        when 401
          raise AdvisoryRequestError.new("GitHub API rejected the credentials (check --github-token or GITHUB_TOKEN)")
        when 403
          # 403 also covers plain "forbidden"; only latch the short-circuit
          # when the response actually says the quota is spent.
          if rate_limited?(response)
            @rate_limited = true
            raise AdvisoryRequestError.new(rate_limit_message(response))
          end
          raise AdvisoryRequestError.new("GitHub API returned 403 Forbidden for #{path}")
        when 404, 422
          # Nothing to report for this repository, not a failure.
          log("GitHub API returned #{response.status_code} for #{path} — no advisories found")
          {"[]", nil, false}
        else
          raise AdvisoryRequestError.new("GitHub API returned #{response.status_code}")
        end
      end
    end

    # One `<uri>; params` entry of an RFC 8288 Link header. Capturing the URI
    # with `[^>]+` lets it contain commas, and the parameter run stops at the
    # next `<`.
    #
    # Splitting the header on "," broke on a URI that itself contains one
    # (`?affects=a,b`), and requiring the quoted form missed `rel=next`, which
    # RFC 8288 permits. Either way pagination stopped early and the trailing
    # advisories were dropped without a word — silent under-reporting.
    LINK_ENTRY_PATTERN = /<([^>]+)>([^<]*)/
    LINK_REL_NEXT      = /(?:\A|[;,\s])rel\s*=\s*"?next"?/i

    private def parse_next_link(link_header : String?) : String?
      return unless link_header

      link_header.scan(LINK_ENTRY_PATTERN) do |match|
        next unless match[2].matches?(LINK_REL_NEXT)
        begin
          uri = URI.parse(match[1])
        rescue URI::Error
          next
        end
        # Only the path and query are reused; the request always goes back to
        # @api_base, so a Link header cannot redirect us to another host.
        path = uri.path
        next unless path.starts_with?('/')
        return uri.query ? "#{path}?#{uri.query}" : path
      end

      nil
    end

    private def log(message : String)
      Shards::Audit.stderr.puts("[GitHub] #{sanitize_log(message)}") if @verbose
    end

    private def sanitize_log(message : String) : String
      if token = @token
        message.gsub(token, "[REDACTED]")
      else
        message
      end
    end
  end
end
