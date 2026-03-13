require "json"

module Shards::Audit
  class GithubClient
    include HttpRetry
    include HttpClient
    include GithubParser
    include AdvisorySource

    GITHUB_API_BASE = "https://api.github.com"

    def initialize(@token : String? = nil, @timeout : Int32 = 30, @verbose : Bool = false, @cache : Cache? = nil)
    end

    def scan(dependencies : Array(Dependency)) : Array(Vulnerability)
      github_deps = dependencies.select(&.github?)
      return [] of Vulnerability if github_deps.empty?

      vulnerabilities = [] of Vulnerability

      github_deps.each do |dep|
        next unless owner_repo = dep.github_owner_repo
        begin
          vulns = query_advisories(owner_repo, dep.name)
          vulnerabilities.concat(vulns)
        rescue ex : IO::Error | Socket::ConnectError | JSON::ParseException
          log("Failed to query advisories for #{owner_repo}: #{ex.message}")
        end
      end

      vulnerabilities
    end

    private def query_advisories(owner_repo : String, dep_name : String) : Array(Vulnerability)
      cache_key = "github/#{owner_repo}.json"

      if cache = @cache
        if cached = cache.get(cache_key)
          log("Cache hit for #{owner_repo}")
          return parse_advisories(cached, dep_name)
        end
      end

      log("Querying GitHub advisories for #{owner_repo}")

      path = "/advisories?affects=#{owner_repo}&per_page=100"
      response = make_request("GET", path)

      if cache = @cache
        cache.set(cache_key, response)
      end

      parse_advisories(response, dep_name)
    end

    private def make_request(method : String, path : String) : String
      with_retry do
        headers = HTTP::Headers{
          "Accept"               => "application/vnd.github+json",
          "X-GitHub-Api-Version" => "2022-11-28",
          "User-Agent"           => "shards-audit/#{VERSION}",
        }

        if token = @token
          headers["Authorization"] = "Bearer #{token}"
        end

        response = http_request(GITHUB_API_BASE, method, path, headers)

        if retryable_status?(response.status_code)
          raise IO::Error.new("GitHub API returned #{response.status_code} (retryable)")
        end

        case response.status_code
        when 200
          response.body
        when 403
          raise IO::Error.new("GitHub API rate limit exceeded (use --github-token for higher limits)")
        when 422
          log("GitHub API returned 422 for #{path} — no advisories found")
          "[]"
        else
          raise IO::Error.new("GitHub API returned #{response.status_code}")
        end
      end
    end

    private def log(message : String)
      STDERR.puts("[GitHub] #{sanitize_log(message)}") if @verbose
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
