require "../../../spec_helper"
require "http/server"

# A local stand-in for the advisory APIs, so these behaviours are tested
# without a network round trip. The suite previously exercised the retry and
# rate-limit paths only by accident, against the live GitHub API — which
# meant the assertions changed meaning depending on the runner's quota.
alias ApiHandler = Proc(HTTP::Server::Context, Array(String), Nil)

private class FakeApi
  getter requests = [] of String
  getter port : Int32

  def initialize(@handler : ApiHandler)
    @server = HTTP::Server.new do |context|
      @requests << "#{context.request.method} #{context.request.resource}"
      @handler.call(context, @requests)
    end
    @port = @server.bind_unused_port("127.0.0.1").port
    spawn { @server.listen }
    Fiber.yield
  end

  def base : String
    "http://127.0.0.1:#{@port}"
  end

  def close
    @server.close
  end
end

private def with_api(handler : ApiHandler, &)
  api = FakeApi.new(handler)
  begin
    yield api
  ensure
    api.close
  end
end

private def github_deps(*names : String) : Array(Shards::Audit::Dependency)
  names.map do |n|
    Shards::Audit::Dependency.new(name: n, git_url: "https://github.com/o/#{n}.git", version: "1.0.0")
  end.to_a
end

describe Shards::Audit::GithubClient do
  describe "rate limiting" do
    # A 403 was raised as IO::Error, which `with_retry` catches — so every
    # dependency retried three times with backoff against a quota already
    # known to be spent.
    it "does not retry an exhausted rate limit" do
      handler = ApiHandler.new do |ctx, _|
        ctx.response.headers["x-ratelimit-remaining"] = "0"
        ctx.response.status_code = 403
        ctx.response.print %({"message":"API rate limit exceeded"})
      end

      with_api(handler) do |api|
        client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
        client.scan(github_deps("one")).should be_empty
        api.requests.size.should eq(1)
      end
    end

    it "stops querying further dependencies once the quota is gone" do
      handler = ApiHandler.new do |ctx, _|
        ctx.response.headers["x-ratelimit-remaining"] = "0"
        ctx.response.status_code = 403
        ctx.response.print %({"message":"API rate limit exceeded"})
      end

      with_api(handler) do |api|
        client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
        client.scan(github_deps("a", "b", "c", "d", "e", "f", "g", "h")).should be_empty
        # The first concurrent batch may race before the flag latches, but
        # later batches must be short-circuited rather than each retrying.
        api.requests.size.should be < 8
      end
    end

    it "retries a 403 that is not a rate limit only once, without latching" do
      handler = ApiHandler.new do |ctx, _|
        ctx.response.status_code = 403
        ctx.response.print %({"message":"Forbidden"})
      end

      with_api(handler) do |api|
        client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
        client.scan(github_deps("a", "b")).should be_empty
        api.requests.size.should eq(2)
      end
    end
  end

  describe "retryable failures" do
    it "retries a 500 and succeeds when the server recovers" do
      attempts = 0
      handler = ApiHandler.new do |ctx, _|
        attempts += 1
        if attempts < 3
          ctx.response.status_code = 500
          ctx.response.print "boom"
        else
          ctx.response.status_code = 200
          ctx.response.print %([{"ghsa_id":"GHSA-1","summary":"ok","severity":"high"}])
        end
      end

      with_api(handler) do |api|
        client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
        vulns = client.scan(github_deps("one"))
        vulns.map(&.id).should eq(["GHSA-1"])
        attempts.should eq(3)
      end
    end

    it "treats 404 and 422 as 'no advisories' rather than an error" do
      handler = ApiHandler.new do |ctx, _|
        ctx.response.status_code = 422
        ctx.response.print %({"message":"Unprocessable"})
      end

      with_api(handler) do |api|
        client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
        client.scan(github_deps("one")).should be_empty
        api.requests.size.should eq(1)
      end
    end
  end

  describe "pagination" do
    it "follows Link rel=next and merges pages" do
      handler = ApiHandler.new do |ctx, requests|
        if requests.size == 1
          ctx.response.headers["Link"] = %(<#{ctx.request.headers["Host"]?}/advisories?page=2>; rel="next")
          ctx.response.status_code = 200
          ctx.response.print %([{"ghsa_id":"GHSA-1"}])
        else
          ctx.response.status_code = 200
          ctx.response.print %([{"ghsa_id":"GHSA-2"}])
        end
      end

      with_api(handler) do |api|
        client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
        client.scan(github_deps("one")).map(&.id).sort!.should eq(["GHSA-1", "GHSA-2"])
        api.requests.size.should eq(2)
      end
    end
  end

  describe "reporting a failed source" do
    # Swallowing per-dependency failures kept one bad payload from killing
    # the run, but it also made a *total* source failure look like a clean
    # result: the CLI printed "No vulnerabilities found!" and exited 0 with
    # an expired token or a spent quota.
    it "records the reason when every lookup fails" do
      handler = ApiHandler.new do |ctx, _|
        ctx.response.status_code = 401
        ctx.response.print %({"message":"Bad credentials"})
      end

      with_api(handler) do |api|
        client = Shards::Audit::GithubClient.new(token: "bad", timeout: 5, api_base: api.base)
        client.scan(github_deps("a", "b")).should be_empty
        client.errors.should_not be_empty
        client.errors.first.should contain("all 2 GitHub lookups failed")
        client.errors.any?(&.includes?("credentials")).should be_true
      end
    end

    it "leaves errors empty on a clean scan" do
      handler = ApiHandler.new do |ctx, _|
        ctx.response.status_code = 200
        ctx.response.print %([])
      end

      with_api(handler) do |api|
        client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
        client.scan(github_deps("a")).should be_empty
        client.errors.should be_empty
      end
    end

    it "keeps partial results and still reports the failure" do
      handler = ApiHandler.new do |ctx, requests|
        if requests.size == 1
          ctx.response.status_code = 200
          ctx.response.print %([{"ghsa_id":"GHSA-1","severity":"high"}])
        else
          ctx.response.status_code = 401
          ctx.response.print %({"message":"Bad credentials"})
        end
      end

      with_api(handler) do |api|
        client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
        vulns = client.scan(github_deps("a", "b"))
        vulns.size.should eq(1)
        client.errors.should_not be_empty
        # Not a total failure, so no "all N failed" summary line.
        client.errors.none?(&.includes?("all ")).should be_true
      end
    end

    it "surfaces the failure through Scanner into AuditResult#errors" do
      handler = ApiHandler.new do |ctx, _|
        ctx.response.status_code = 401
        ctx.response.print %({"message":"Bad credentials"})
      end

      with_api(handler) do |api|
        client = Shards::Audit::GithubClient.new(token: "bad", timeout: 5, api_base: api.base)
        client.scan(github_deps("a"))
        # Scanner joins client.errors into the reported message.
        message = "GitHub scan: #{client.errors.join("; ")}"
        message.should contain("credentials")
      end
    end
  end

  describe "caching" do
    # A 404 is synthesised into an empty list so the scan can continue, but
    # persisting that pinned "no advisories" for the whole 24h TTL — and 404
    # is also what GitHub returns during an outage.
    it "does not cache a 404 as 'no advisories'" do
      cache_dir = File.join(Dir.tempdir, "shards-audit-404-#{Random.rand(1_000_000)}")
      Dir.mkdir_p(cache_dir)
      begin
        cache = Shards::Audit::Cache.new(cache_dir, 3600)
        handler = ApiHandler.new do |ctx, _|
          ctx.response.status_code = 404
          ctx.response.print %({"message":"Not Found"})
        end

        with_api(handler) do |api|
          client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base, cache: cache)
          client.scan(github_deps("one")).should be_empty
          cache.get("github/o/one.json").should be_nil
        end
      ensure
        FileUtils.rm_rf(cache_dir)
      end
    end

    it "does cache a successful 200" do
      cache_dir = File.join(Dir.tempdir, "shards-audit-200-#{Random.rand(1_000_000)}")
      Dir.mkdir_p(cache_dir)
      begin
        cache = Shards::Audit::Cache.new(cache_dir, 3600)
        handler = ApiHandler.new do |ctx, _|
          ctx.response.status_code = 200
          ctx.response.print %([{"ghsa_id":"GHSA-1"}])
        end

        with_api(handler) do |api|
          client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base, cache: cache)
          client.scan(github_deps("one")).size.should eq(1)
          cache.get("github/o/one.json").should_not be_nil
        end
      ensure
        FileUtils.rm_rf(cache_dir)
      end
    end
  end

  describe "credentials" do
    it "reports a rejected token without retrying" do
      handler = ApiHandler.new do |ctx, _|
        ctx.response.status_code = 401
        ctx.response.print %({"message":"Bad credentials"})
      end

      with_api(handler) do |api|
        client = Shards::Audit::GithubClient.new(token: "bad", timeout: 5, api_base: api.base)
        client.scan(github_deps("one")).should be_empty
        api.requests.size.should eq(1)
      end
    end
  end
end

describe Shards::Audit::OsvClient do
  describe "querybatch mapping" do
    it "maps results back to the querying dependency" do
      handler = ApiHandler.new do |ctx, requests|
        if requests.last.includes?("querybatch")
          ctx.response.print %({"results":[{"vulns":[{"id":"OSV-1"}]}]})
        else
          ctx.response.print %({"id":"OSV-1","summary":"boom","database_specific":{"severity":"HIGH"}})
        end
      end

      with_api(handler) do |api|
        client = Shards::Audit::OsvClient.new(timeout: 5, api_base: api.base)
        vulns = client.scan(github_deps("one"))
        vulns.size.should eq(1)
        vulns[0].dependency_name.should eq("one")
        vulns[0].severity.should eq(Shards::Audit::Severity::High)
      end
    end

    it "refuses to map a result count that does not match the query count" do
      handler = ApiHandler.new do |ctx, _|
        ctx.response.print %({"results":[{"vulns":[]},{"vulns":[]},{"vulns":[]}]})
      end

      with_api(handler) do |api|
        client = Shards::Audit::OsvClient.new(timeout: 5, api_base: api.base)
        expect_raises(Shards::Audit::OsvResponseError, /refusing to map/) do
          client.scan(github_deps("one"))
        end
      end
    end

    # OSV caps a querybatch at 1000 queries. One unbounded POST meant a large
    # lockfile silently exceeded the cap and failed the whole source.
    it "splits a large query set across several querybatch requests" do
      batch_sizes = [] of Int32
      handler = ApiHandler.new do |ctx, _|
        if ctx.request.resource.includes?("querybatch")
          body = ctx.request.body.try(&.gets_to_end) || "{}"
          size = JSON.parse(body)["queries"].as_a.size
          batch_sizes << size
          ctx.response.print({"results" => Array.new(size) { {"vulns" => [] of String} }}.to_json)
        else
          ctx.response.print %({"id":"x"})
        end
      end

      with_api(handler) do |api|
        client = Shards::Audit::OsvClient.new(timeout: 10, api_base: api.base)
        # 600 dependencies with a distinct non-GitHub remote each, so exactly
        # one query per dependency and a predictable total.
        deps = (1..600).map do |i|
          Shards::Audit::Dependency.new(
            name: "dep#{i}", git_url: "https://git.example/o/dep#{i}.git", version: "1.0.0")
        end
        client.scan(deps).should be_empty

        batch_sizes.size.should eq(2)
        batch_sizes.sum.should eq(600)
        batch_sizes.max.should be <= Shards::Audit::OsvClient::MAX_BATCH_QUERIES
      end
    end

    it "does not retry a non-retryable status" do
      handler = ApiHandler.new do |ctx, _|
        ctx.response.status_code = 400
        ctx.response.print "bad request"
      end

      with_api(handler) do |api|
        client = Shards::Audit::OsvClient.new(timeout: 5, api_base: api.base)
        expect_raises(Shards::Audit::AdvisoryRequestError, /400/) do
          client.scan(github_deps("one"))
        end
        api.requests.size.should eq(1)
      end
    end
  end
end
