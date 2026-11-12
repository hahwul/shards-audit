require "../../spec_helper"
require "http/server"

# Regressions for advisories the audit could not see, and for results it
# reported as clean when it had not actually looked.

private class RecordingApi
  getter port : Int32
  getter requests = [] of String
  getter authorizations = [] of String

  def initialize(&@handler : HTTP::Server::Context -> Nil)
    @server = HTTP::Server.new do |ctx|
      @requests << ctx.request.resource
      @authorizations << (ctx.request.headers["Authorization"]? || "")
      @handler.call(ctx)
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

private def with_api(&block : RecordingApi -> Nil)
  api = RecordingApi.new do |ctx|
    ctx.response.status_code = 200
    ctx.response.print "[]"
  end
  begin
    block.call(api)
  ensure
    api.close
  end
end

# Serves one OSV advisory body for every `/v1/vulns/{id}` lookup, and claims
# every queried dependency is affected by it.
private def osv_api(vuln_body : String, vulns_status : Int32 = 200) : RecordingApi
  RecordingApi.new do |ctx|
    if ctx.request.resource.includes?("querybatch")
      body = ctx.request.body.try(&.gets_to_end) || "{}"
      count = JSON.parse(body)["queries"].as_a.size
      ctx.response.print({"results" => Array.new(count) { {"vulns" => [{"id" => "OSV-1"}]} }}.to_json)
    else
      ctx.response.status_code = vulns_status
      ctx.response.print vuln_body
    end
  end
end

private def dep(version : String = "1.5.0") : Shards::Audit::Dependency
  Shards::Audit::Dependency.new(
    name: "router", git_url: "https://github.com/o/router.cr.git", version: version)
end

private def scan_osv(api : RecordingApi, version : String = "1.5.0") : Array(Shards::Audit::Vulnerability)
  Shards::Audit::OsvClient.new(timeout: 5, api_base: api.base).scan([dep(version)])
end

private class StubScanner < Shards::Audit::Scanner
  setter osv_base : String = ""
  setter github_base : String = ""

  protected def build_osv_client : Shards::Audit::OsvClient
    Shards::Audit::OsvClient.new(timeout: 5, api_base: @osv_base)
  end

  protected def build_github_client : Shards::Audit::GithubClient
    Shards::Audit::GithubClient.new(timeout: 5, api_base: @github_base)
  end
end

private class RetryProbe
  include Shards::Audit::HttpRetry

  @verbose = false
end

describe "OSV affected[].versions" do
  # OSV §affected: a version matches when it falls inside a range *or* when
  # it is named in the enumerated `versions` list. Only the ranges were read,
  # so an advisory that enumerates the affected git tags and carries ranges
  # for another packaging of the same code judged an explicitly-listed
  # version unaffected. A false negative — the failure this tool exists to
  # prevent.
  enumerated = %({
    "id": "OSV-1",
    "summary": "enumerated versions",
    "affected": [
      {"package": {"ecosystem":"GIT","name":"https://github.com/o/router.cr"},
       "versions": ["1.5.0", "1.6.0"]},
      {"package": {"ecosystem":"npm","name":"router"},
       "ranges": [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}
    ]
  })

  it "reports a version named in the enumerated list" do
    api = osv_api(enumerated)
    begin
      vulns = scan_osv(api, "1.5.0")
      vulns.size.should eq(1)
      vulns[0].affected_versions.should eq(["1.5.0", "1.6.0"])
      vulns[0].affected?("1.5.0").should be_true
    ensure
      api.close
    end
  end

  it "matches a v-prefixed spelling of an enumerated version" do
    api = osv_api(enumerated)
    begin
      scan_osv(api).first.affected?("v1.6.0").should be_true
    ensure
      api.close
    end
  end

  # The list only ever widens the match. A version that is neither listed nor
  # inside a range is still filtered exactly as before.
  it "still filters a version that is neither listed nor in range" do
    api = osv_api(enumerated)
    begin
      scan_osv(api).first.affected?("2.0.0").should be_false
    ensure
      api.close
    end
  end

  # OSV §affected[].versions enumerates the affected versions, so a
  # versions-only entry clears every version it does not list. It used to
  # match every version.
  it "judges a versions-only advisory by its list" do
    api = osv_api(%({"id":"OSV-1","affected":[{"versions":["v1.0.0", "1.1.0"]}]}))
    begin
      vuln = scan_osv(api).first
      vuln.affected?("9.9.9").should be_false
      vuln.affected?("1.0.0").should be_true
      vuln.affected?("v1.1.0").should be_true
    ensure
      api.close
    end
  end

  it "still assumes affected when the advisory has neither ranges nor versions" do
    api = osv_api(%({"id":"OSV-1","affected":[{"package":{"ecosystem":"GIT","name":"x"}}]}))
    begin
      scan_osv(api).first.affected?("9.9.9").should be_true
    ensure
      api.close
    end
  end

  it "does not let another entry's versions list decide a bound-less entry" do
    api = osv_api(%({"id":"OSV-1","affected":[
      {"package":{"ecosystem":"npm","name":"router"},"versions":["1.0.0"]},
      {"package":{"ecosystem":"GIT","name":"https://github.com/o/router.cr"}}]}))
    begin
      scan_osv(api).first.affected?("2.3.0").should be_true
    ensure
      api.close
    end
  end

  it "does not narrow an unconstrained record when merged with a versions-only one" do
    a = Shards::Audit::Vulnerability.new(id: "GHSA-x", dependency_name: "router")
    b = Shards::Audit::Vulnerability.new(id: "GHSA-x", dependency_name: "router", affected_versions: ["1.5.0"])
    a.merge(b).affected?("9.9.9").should be_true
    b.merge(a).affected?("9.9.9").should be_true
  end

  it "unions a versions-only record with a ranged one on merge" do
    a = Shards::Audit::Vulnerability.new(id: "GHSA-x", dependency_name: "router", affected_versions: ["1.5.0"])
    b = Shards::Audit::Vulnerability.new(id: "GHSA-x", dependency_name: "router",
      affected_ranges: [Shards::Audit::SemverRange.new(fixed: Shards::Audit::Semver.parse("1.0.0"))])
    merged = a.merge(b)
    merged.affected?("1.5.0").should be_true
    merged.affected?("0.9.0").should be_true
    merged.affected?("2.0.0").should be_false
  end

  it "carries the enumerated versions through a merge" do
    a = Shards::Audit::Vulnerability.new(id: "GHSA-x", dependency_name: "router",
      affected_ranges: [Shards::Audit::SemverRange.new(fixed: Shards::Audit::Semver.parse("1.0.0"))],
      affected_versions: ["1.5.0"])
    b = Shards::Audit::Vulnerability.new(id: "GHSA-x", dependency_name: "router",
      affected_ranges: [Shards::Audit::SemverRange.new(fixed: Shards::Audit::Semver.parse("1.0.0"))],
      affected_versions: ["1.6.0"])

    merged = a.merge(b)
    merged.affected_versions.should eq(["1.5.0", "1.6.0"])
    merged.affected?("1.6.0").should be_true
  end
end

describe "withdrawn advisories" do
  # OSV §withdrawn and GitHub's `withdrawn_at` both mean the entry has been
  # retracted. Reporting one anyway kept failing a CI job until somebody
  # added the id to `ignore:` by hand.
  it "does not report an OSV entry with a withdrawn timestamp" do
    api = osv_api(%({"id":"OSV-1","summary":"retracted","withdrawn":"2024-01-01T00:00:00Z",
      "affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}))
    begin
      scan_osv(api).should be_empty
    ensure
      api.close
    end
  end

  it "does not count a withdrawn OSV entry as a failed lookup" do
    api = osv_api(%({"id":"OSV-1","withdrawn":"2024-01-01T00:00:00Z"}))
    begin
      client = Shards::Audit::OsvClient.new(timeout: 5, api_base: api.base)
      client.scan([dep]).should be_empty
      client.errors.should be_empty
    ensure
      api.close
    end
  end

  it "does not report a GitHub advisory with withdrawn_at" do
    api = RecordingApi.new do |ctx|
      ctx.response.print %([{"ghsa_id":"GHSA-a","summary":"s","severity":"high",
        "withdrawn_at":"2024-01-01T00:00:00Z"}])
    end
    begin
      Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base).scan([dep]).should be_empty
    ensure
      api.close
    end
  end

  # A token with repository access also sees draft and triage advisories,
  # which are unreviewed reports rather than confirmed vulnerabilities.
  it "does not report a draft or triage repository advisory" do
    api = RecordingApi.new do |ctx|
      ctx.response.print %([{"ghsa_id":"GHSA-a","summary":"s","state":"draft"},
        {"ghsa_id":"GHSA-b","summary":"s","state":"triage"},
        {"ghsa_id":"GHSA-c","summary":"s","state":"published"}])
    end
    begin
      vulns = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base).scan([dep])
      vulns.map(&.id).should eq(["GHSA-c"])
    ensure
      api.close
    end
  end
end

describe "GitHub advisory source" do
  # `/advisories?affects=owner/repo` searches the *global* advisory database,
  # whose `affects` filter matches package names inside a GitHub-supported
  # ecosystem — and Crystal is not one. Verified against the live API: the
  # query answers `[]` for every shard, and GHSA-wqh5-7w63-pm68, a published
  # Crystal advisory, is not in the global database at all. The source could
  # therefore never contribute a finding. Repository security advisories are
  # where a shard maintainer publishes, and they are readable without a
  # token.
  it "queries the repository's security advisories, not the global database" do
    with_api do |api|
      Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base).scan([dep])
      api.requests.size.should eq(1)
      api.requests[0].should start_with("/repos/o/router.cr/security-advisories")
      api.requests[0].should contain("state=published")
      api.requests[0].should_not contain("affects=")
    end
  end

  # `patched_versions` is what the repository advisory schema calls the field
  # the global schema names `first_patched_version`, so every advisory from
  # this endpoint reported "no fix available".
  it "reads the fix version from patched_versions" do
    api = RecordingApi.new do |ctx|
      ctx.response.print %([{"ghsa_id":"GHSA-a","summary":"s","severity":"low","state":"published",
        "vulnerabilities":[{"package":{"ecosystem":"","name":"router"},
        "vulnerable_version_range":"< 1.20.0","patched_versions":"1.20.0"}]}])
    end
    begin
      vulns = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base).scan([dep("1.19.0")])
      vulns.size.should eq(1)
      vulns[0].fixed_version.should eq("1.20.0")
      vulns[0].affected?("1.19.0").should be_true
      vulns[0].affected?("1.20.0").should be_false
    ensure
      api.close
    end
  end

  it "still prefers first_patched_version when both are present" do
    api = RecordingApi.new do |ctx|
      ctx.response.print %([{"ghsa_id":"GHSA-a","summary":"s",
        "vulnerabilities":[{"first_patched_version":"2.0.0","patched_versions":"9.9.9"}]}])
    end
    begin
      Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
        .scan([dep]).first.fixed_version.should eq("2.0.0")
    ensure
      api.close
    end
  end

  # The old cache key held the global database's answer — an empty list for
  # every shard. Serving it after the upgrade would pin "no advisories" for
  # the whole TTL.
  it "does not serve a cache entry written by the previous endpoint" do
    cache_dir = File.join(Dir.tempdir, "shards-audit-cachekey-#{Random.rand(1_000_000)}")
    Dir.mkdir_p(cache_dir)
    begin
      cache = Shards::Audit::Cache.new(cache_dir, 3600)
      cache.set("github/o/router.cr.json", "[]")

      api = RecordingApi.new do |ctx|
        ctx.response.print %([{"ghsa_id":"GHSA-a","summary":"s","severity":"high"}])
      end
      begin
        client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base, cache: cache)
        client.scan([dep]).map(&.id).should eq(["GHSA-a"])
      ensure
        api.close
      end
    ensure
      FileUtils.rm_rf(cache_dir)
    end
  end

  # `GITHUB_TOKEN: ${{ secrets.MISSING }}` exports an empty string. It was
  # read as a token, so every request went out as `Authorization: Bearer `
  # and GitHub answered 401 — the whole source failed for a run that would
  # have worked unauthenticated.
  it "treats a blank token as no token" do
    with_api do |api|
      client = Shards::Audit::GithubClient.new(token: "", timeout: 5, api_base: api.base)
      client.scan([dep])
      api.authorizations.should eq([""])
      client.errors.should be_empty
    end
  end

  it "reads no token from a blank GITHUB_TOKEN" do
    previous = ENV["GITHUB_TOKEN"]?
    begin
      ENV["GITHUB_TOKEN"] = ""
      Shards::Audit::Config.new.github_token.should be_nil
    ensure
      if previous
        ENV["GITHUB_TOKEN"] = previous
      else
        ENV.delete("GITHUB_TOKEN")
      end
    end
  end
end

describe "incomplete audits" do
  # The batch query already told us these advisories exist, so failing to
  # fetch their details is missing findings, not a clean result. Both were
  # answered with nil, and `scan` returned an empty array with nothing to
  # say about it: "No vulnerabilities found!", exit 0.
  it "reports OSV advisory lookups that failed" do
    api = osv_api(%({"message":"nope"}), vulns_status: 400)
    begin
      client = Shards::Audit::OsvClient.new(timeout: 5, api_base: api.base)
      client.scan([dep]).should be_empty
      client.errors.first.should contain("1 of 1 OSV advisory lookups failed")
    ensure
      api.close
    end
  end

  it "surfaces an OSV lookup failure through the scanner" do
    osv = osv_api(%({"message":"nope"}), vulns_status: 400)
    github = RecordingApi.new(&.response.print("[]"))
    begin
      scanner = StubScanner.new(Shards::Audit::Config.new(no_cache: true))
      scanner.osv_base = osv.base
      scanner.github_base = github.base
      result = scanner.scan([dep])

      result.vulnerabilities.should be_empty
      result.errors.join(" ").should contain("OSV scan:")
    ensure
      osv.close
      github.close
    end
  end

  describe "exit codes" do
    config = Shards::Audit::Config.new

    it "is EXIT_CLEAN for a clean run with no errors" do
      Shards::Audit::CLI.exit_code_for(config, Shards::Audit::AuditResult.new)
        .should eq(Shards::Audit::CLI::EXIT_CLEAN)
    end

    it "is EXIT_ERROR when a source failed and nothing was found" do
      result = Shards::Audit::AuditResult.new
      result.errors << "OSV scan failed: connection refused"
      Shards::Audit::CLI.exit_code_for(config, result)
        .should eq(Shards::Audit::CLI::EXIT_ERROR)
    end

    it "is EXIT_VULNS when findings exist, whatever else failed" do
      result = Shards::Audit::AuditResult.new
      result.errors << "GitHub scan: all 1 GitHub lookups failed"
      result.vulnerabilities << Shards::Audit::Vulnerability.new(id: "GHSA-a")
      Shards::Audit::CLI.exit_code_for(config, result)
        .should eq(Shards::Audit::CLI::EXIT_VULNS)
    end

    it "stays EXIT_CLEAN under --exit-zero" do
      result = Shards::Audit::AuditResult.new
      result.errors << "OSV scan failed: connection refused"
      Shards::Audit::CLI.exit_code_for(Shards::Audit::Config.new(exit_zero: true), result)
        .should eq(Shards::Audit::CLI::EXIT_CLEAN)
    end
  end
end

describe "Retry-After" do
  probe = RetryProbe.new

  it "parses a delay given in seconds" do
    probe.retry_after_seconds("120").should eq(120.0)
  end

  it "parses an HTTP-date into a delay from now" do
    at = (Time.utc + 42.seconds).to_s("%a, %d %b %Y %H:%M:%S GMT")
    delay = probe.retry_after_seconds(at).not_nil!
    delay.should be_close(42.0, 2.0)
  end

  it "treats a date already past as retry now" do
    at = (Time.utc - 1.hour).to_s("%a, %d %b %Y %H:%M:%S GMT")
    probe.retry_after_seconds(at).should eq(0.0)
  end

  it "ignores a missing or unparseable value" do
    probe.retry_after_seconds(nil).should be_nil
    probe.retry_after_seconds("  ").should be_nil
    probe.retry_after_seconds("soon").should be_nil
    probe.retry_after_seconds("-5").should be_nil
  end

  # Retrying after 0.5s against a window the server said would not reopen for
  # a minute burns the remaining attempts and fails the dependency.
  it "waits as long as the server asked" do
    ex = Shards::Audit::RetryableResponseError.new("429", 12.0)
    probe.retry_delay(ex, 1, 0.5).should eq(12.0)
  end

  it "caps the server's advice at MAX_RETRY_DELAY" do
    ex = Shards::Audit::RetryableResponseError.new("429", 9999.0)
    probe.retry_delay(ex, 1, 0.5).should eq(Shards::Audit::HttpRetry::MAX_RETRY_DELAY)
  end

  it "falls back to exponential backoff without the header" do
    probe.retry_delay(IO::Error.new("boom"), 3, 0.5).should be_close(2.0, 0.21)
  end

  # A 429 whose quota counter has already reached zero is the primary rate
  # limit; no amount of retrying reopens it.
  it "does not retry a 429 that reports an exhausted quota" do
    api = RecordingApi.new do |ctx|
      ctx.response.headers["x-ratelimit-remaining"] = "0"
      ctx.response.status_code = 429
      ctx.response.print %({"message":"API rate limit exceeded"})
    end
    begin
      client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
      client.scan([dep]).should be_empty
      api.requests.size.should eq(1)
      client.errors.join(" ").should contain("rate limit")
    ensure
      api.close
    end
  end
end

describe "GitHub repository advisory responses" do
  advisory = %([{"ghsa_id":"GHSA-r","summary":"s","severity":"high","state":"published",
    "vulnerabilities":[{"vulnerable_version_range":"< 2.0.0","patched_versions":"2.0.0"}]}])

  # A renamed repository answers 301 with a Location on the API host.
  it "follows a same-host redirect for a renamed repository" do
    api = RecordingApi.new do |ctx|
      if ctx.request.resource.starts_with?("/repos/")
        ctx.response.status_code = 301
        ctx.response.headers["Location"] = "http://127.0.0.1:#{ctx.request.local_address.as(Socket::IPAddress).port}/repositories/42/security-advisories?state=published"
      else
        ctx.response.print advisory
      end
    end
    begin
      client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
      client.scan([dep]).map(&.id).should eq(["GHSA-r"])
      client.errors.should be_empty
      api.requests.last.should start_with("/repositories/42/")
    ensure
      api.close
    end
  end

  # Each hop gets its own retry budget; recursing from inside `with_retry`
  # multiplied the attempts (20 requests for one hop to a 503).
  it "does not nest retries across a redirect" do
    api = RecordingApi.new do |ctx|
      if ctx.request.resource.starts_with?("/repos/")
        ctx.response.status_code = 301
        ctx.response.headers["Location"] = "/repositories/42/security-advisories"
      else
        ctx.response.headers["Retry-After"] = "0"
        ctx.response.status_code = 503
      end
    end
    begin
      client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
      client.scan([dep]).should be_empty
      client.errors.should_not be_empty
      api.requests.size.should eq(5)
    ensure
      api.close
    end
  end

  it "does not follow a redirect to another host" do
    api = RecordingApi.new do |ctx|
      ctx.response.status_code = 301
      ctx.response.headers["Location"] = "https://evil.example/repositories/42/security-advisories"
    end
    begin
      client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
      client.scan([dep]).should be_empty
      api.requests.size.should eq(1)
      client.errors.join.should contain("301")
    ensure
      api.close
    end
  end

  it "treats a non-array 200 body as a failed lookup, not as no advisories" do
    api = RecordingApi.new { |ctx| ctx.response.print %({"message":"unexpected"}) }
    begin
      client = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
      client.scan([dep]).should be_empty
      client.errors.should_not be_empty
    ensure
      api.close
    end
  end

  # kemalcr/kemal GHSA-89xc-29wg-6mm5 publishes `"patched_versions": "none"`.
  it "does not report a patched_versions of 'none' as a fix version" do
    api = RecordingApi.new do |ctx|
      ctx.response.print %([{"ghsa_id":"GHSA-n","summary":"s","state":"published",
        "vulnerabilities":[{"vulnerable_version_range":">= 1.0.0, <= 2.0.0","patched_versions":"none"}]}])
    end
    begin
      Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base)
        .scan([dep]).first.fixed_version.should be_nil
    ensure
      api.close
    end
  end

  # kemalcr/kemal GHSA-2x8p-5jvx-v7jw: `cvss` is null, the score lives only
  # under `cvss_severities.cvss_v4`.
  it "reads a CVSS v4-only score from cvss_severities" do
    api = RecordingApi.new do |ctx|
      ctx.response.print %([{"ghsa_id":"GHSA-v4","summary":"s","severity":"high","state":"published",
        "cvss":{"score":null,"vector_string":null},
        "cvss_severities":{"cvss_v3":{"score":null,"vector_string":null},"cvss_v4":{"score":8.7,"vector_string":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}},
        "vulnerabilities":[]}])
    end
    begin
      vuln = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base).scan([dep]).first
      vuln.cvss_score.should eq(8.7)
      vuln.severity.should eq(Shards::Audit::Severity::High)
    ensure
      api.close
    end
  end
end

describe "OSV querybatch responses" do
  it "rejects a reply without a results array instead of reporting every dependency clean" do
    api = RecordingApi.new(&.response.print("{}"))
    begin
      expect_raises(Shards::Audit::OsvResponseError) { scan_osv(api) }
    ensure
      api.close
    end
  end

  it "rejects a result entry that is not an object" do
    api = RecordingApi.new do |ctx|
      body = ctx.request.body.try(&.gets_to_end) || "{}"
      count = JSON.parse(body)["queries"].as_a.size
      ctx.response.print({"results" => Array.new(count) { nil }}.to_json)
    end
    begin
      expect_raises(Shards::Audit::OsvResponseError) { scan_osv(api) }
    ensure
      api.close
    end
  end
end

describe "non-finite CVSS scores" do
  it "drops an Infinity score instead of crashing the JSON report" do
    api = RecordingApi.new do |ctx|
      ctx.response.print %([{"ghsa_id":"GHSA-inf","summary":"s","severity":"high","state":"published",
        "cvss":{"score":"Infinity"},"vulnerabilities":[]}])
    end
    begin
      vuln = Shards::Audit::GithubClient.new(timeout: 5, api_base: api.base).scan([dep]).first
      vuln.cvss_score.should be_nil
      vuln.severity.should eq(Shards::Audit::Severity::High)
    ensure
      api.close
    end
  end
end
