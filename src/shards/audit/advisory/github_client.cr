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

    MAX_CONCURRENCY = 5

    def scan(dependencies : Array(Dependency)) : Array(Vulnerability)
      github_deps = dependencies.select(&.github?)
      return [] of Vulnerability if github_deps.empty?

      vulnerabilities = [] of Vulnerability
      channel = Channel(Array(Vulnerability)).new(MAX_CONCURRENCY)

      github_deps.each_slice(MAX_CONCURRENCY) do |batch|
        batch.each do |dep|
          spawn do
            vulns = if owner_repo = dep.github_owner_repo
                      begin
                        query_advisories(owner_repo, dep.name)
                      rescue ex : IO::Error | Socket::ConnectError | JSON::ParseException
                        log("Failed to query advisories for #{owner_repo}: #{ex.message}")
                        [] of Vulnerability
                      end
                    else
                      [] of Vulnerability
                    end
            channel.send(vulns)
          end
        end

        batch.size.times do
          vulnerabilities.concat(channel.receive)
        end
      end

      vulnerabilities
    end

    MAX_PAGES = 10

    private def query_advisories(owner_repo : String, dep_name : String) : Array(Vulnerability)
      cache_key = "github/#{owner_repo}.json"

      if cache = @cache
        if cached = cache.get(cache_key)
          log("Cache hit for #{owner_repo}")
          return parse_advisories(cached, dep_name)
        end
      end

      log("Querying GitHub advisories for #{owner_repo}")

      collected = [] of JSON::Any
      path : String? = "/advisories?affects=#{owner_repo}&per_page=100"
      page = 0

      while path && page < MAX_PAGES
        page += 1
        body, next_path = make_request_with_links("GET", path)

        if items = JSON.parse(body).as_a?
          collected.concat(items)
        end

        path = next_path
        log("Following pagination page #{page + 1} for #{owner_repo}") if path
      end

      all_advisories = collected.to_json

      if cache = @cache
        cache.set(cache_key, all_advisories)
      end

      parse_advisories(all_advisories, dep_name)
    end

    private def make_request_with_links(method : String, path : String) : {String, String?}
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
          next_link = parse_next_link(response.headers["Link"]?) if response.headers["Link"]?
          {response.body, next_link}
        when 403
          raise IO::Error.new("GitHub API rate limit exceeded (use --github-token for higher limits)")
        when 422
          log("GitHub API returned 422 for #{path} — no advisories found")
          {"[]", nil}
        else
          raise IO::Error.new("GitHub API returned #{response.status_code}")
        end
      end
    end

    private def parse_next_link(link_header : String?) : String?
      return unless link_header
      link_header.split(',').each do |part|
        if part.includes?("rel=\"next\"")
          if match = part.match(/<([^>]+)>/)
            begin
              uri = URI.parse(match[1])
              return "#{uri.path}?#{uri.query}" if uri.query
              return uri.path
            rescue URI::Error
              next
            end
          end
        end
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
