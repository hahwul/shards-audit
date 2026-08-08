require "../../spec_helper"
require "http/server"

# Exercises the whole path — lockfile, both advisory sources, dedup,
# filtering, every report format — against local stand-ins for the APIs.
# Everything below the CLI was previously only reachable with real network
# calls, so no test covered a run that actually finds something.

private class StubApi
  getter port : Int32

  def initialize(&@handler : HTTP::Server::Context -> Nil)
    @server = HTTP::Server.new { |ctx| @handler.call(ctx) }
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

private OSV_VULN = %({
  "id": "GHSA-vvvv-wwww-xxxx",
  "summary": "Path traversal in the router",
  "aliases": ["CVE-2024-9999"],
  "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected": [{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.5.0"}]}]}],
  "references": [{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-vvvv-wwww-xxxx"}]
})

private def with_stubs(github_body : String, &)
  osv = StubApi.new do |ctx|
    if ctx.request.resource.includes?("querybatch")
      body = ctx.request.body.try(&.gets_to_end) || "{}"
      count = JSON.parse(body)["queries"].as_a.size
      ctx.response.print({"results" => Array.new(count) { {"vulns" => [{"id" => "GHSA-vvvv-wwww-xxxx"}]} }}.to_json)
    else
      ctx.response.print OSV_VULN
    end
  end

  github = StubApi.new do |ctx|
    ctx.response.status_code = 200
    ctx.response.print github_body
  end

  begin
    yield osv, github
  ensure
    osv.close
    github.close
  end
end

private def scan_with(config : Shards::Audit::Config, osv : StubApi, github : StubApi,
                      version : String = "1.2.0") : Shards::Audit::AuditResult
  scanner = StubScanner.new(config)
  scanner.osv_base = osv.base
  scanner.github_base = github.base
  scanner.scan([
    Shards::Audit::Dependency.new(
      name: "router", git_url: "https://github.com/o/router.cr.git", version: version),
  ])
end

describe "end-to-end scan" do
  # GitHub reports the same advisory, but with a sparse record. The merged
  # finding must keep the best of both.
  github_same = %([{"ghsa_id":"GHSA-vvvv-wwww-xxxx","summary":"",
    "html_url":"https://github.com/advisories/GHSA-vvvv-wwww-xxxx",
    "vulnerabilities":[{"first_patched_version":"1.5.0","vulnerable_version_range":">= 1.0.0, < 1.5.0"}]}])

  it "finds, merges and reports a vulnerability from both sources" do
    with_stubs(github_same) do |osv, github|
      result = scan_with(Shards::Audit::Config.new(no_cache: true), osv, github)

      result.dependencies_scanned.should eq(1)
      result.vulnerabilities.size.should eq(1)

      vuln = result.vulnerabilities[0]
      vuln.id.should eq("GHSA-vvvv-wwww-xxxx")
      vuln.dependency_name.should eq("router")
      vuln.severity.should eq(Shards::Audit::Severity::Critical)
      vuln.cvss_score.should eq(9.8)
      vuln.summary.should eq("Path traversal in the router")
      vuln.fixed_version.should eq("1.5.0")
      vuln.source.should eq("OSV, GitHub")
      vuln.aliases.should contain("CVE-2024-9999")
    end
  end

  it "filters out a version outside the affected range" do
    with_stubs(github_same) do |osv, github|
      result = scan_with(Shards::Audit::Config.new(no_cache: true), osv, github, version: "1.5.0")
      result.vulnerabilities.should be_empty
      result.version_filtered_count.should eq(1)
      result.clean?.should be_true
    end
  end

  it "honours --ignore by advisory id" do
    with_stubs(github_same) do |osv, github|
      config = Shards::Audit::Config.new(no_cache: true, ignore_ids: ["GHSA-vvvv-wwww-xxxx"])
      result = scan_with(config, osv, github)
      result.vulnerabilities.should be_empty
      result.ignored_count.should eq(1)
    end
  end

  it "honours --ignore by CVE alias" do
    with_stubs(github_same) do |osv, github|
      config = Shards::Audit::Config.new(no_cache: true, ignore_ids: ["CVE-2024-9999"])
      result = scan_with(config, osv, github)
      result.vulnerabilities.should be_empty
      result.ignored_count.should eq(1)
    end
  end

  it "keeps a critical finding at the highest threshold" do
    with_stubs(github_same) do |osv, github|
      config = Shards::Audit::Config.new(no_cache: true,
        severity_threshold: Shards::Audit::Severity::Critical)
      scan_with(config, osv, github).vulnerabilities.size.should eq(1)
    end
  end

  describe "report rendering of a real finding" do
    it "renders every format without losing the finding" do
      with_stubs(github_same) do |osv, github|
        result = scan_with(Shards::Audit::Config.new(no_cache: true), osv, github)

        json = IO::Memory.new
        Shards::Audit::JsonFormatter.new.format(result, json)
        parsed = JSON.parse(json.to_s)
        parsed["vulnerabilities_found"].as_i.should eq(1)
        parsed["vulnerabilities"][0]["severity"].as_s.should eq("CRITICAL")
        parsed["vulnerabilities"][0]["fixed_version"].as_s.should eq("1.5.0")

        yaml = IO::Memory.new
        Shards::Audit::YamlFormatter.new.format(result, yaml)
        YAML.parse(yaml.to_s)["vulnerabilities"][0]["id"].as_s.should eq("GHSA-vvvv-wwww-xxxx")

        sarif = IO::Memory.new
        Shards::Audit::SarifFormatter.new("shard.lock").format(result, sarif)
        run = JSON.parse(sarif.to_s)["runs"][0]
        run["results"].as_a.size.should eq(1)
        run["results"][0]["level"].as_s.should eq("error")
        run["tool"]["driver"]["rules"].as_a.size.should eq(1)

        toml = IO::Memory.new
        Shards::Audit::TomlFormatter.new.format(result, toml)
        toml.to_s.should contain(%(id = "GHSA-vvvv-wwww-xxxx"))

        table = IO::Memory.new
        Shards::Audit::TableFormatter.new(no_color: true).format(result, table)
        table.to_s.should contain("CRITICAL")
        table.to_s.should contain("Upgrade to >= 1.5.0")
      end
    end
  end

  describe "when GitHub reports a different advisory" do
    github_other = %([{"ghsa_id":"GHSA-aaaa-bbbb-cccc","summary":"Denial of service",
      "severity":"high",
      "vulnerabilities":[{"first_patched_version":"2.0.0","vulnerable_version_range":">= 1.0.0, < 2.0.0"}]}])

    it "reports both findings, most severe first" do
      with_stubs(github_other) do |osv, github|
        result = scan_with(Shards::Audit::Config.new(no_cache: true), osv, github)
        result.vulnerabilities.size.should eq(2)
        result.vulnerabilities.map(&.severity).should eq([
          Shards::Audit::Severity::Critical,
          Shards::Audit::Severity::High,
        ])
      end
    end

    it "drops the lower finding at a critical threshold" do
      with_stubs(github_other) do |osv, github|
        config = Shards::Audit::Config.new(no_cache: true,
          severity_threshold: Shards::Audit::Severity::Critical)
        result = scan_with(config, osv, github)
        result.vulnerabilities.map(&.id).should eq(["GHSA-vvvv-wwww-xxxx"])
        result.filtered_count.should eq(1)
      end
    end
  end
end
