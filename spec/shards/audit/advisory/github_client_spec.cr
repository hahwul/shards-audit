require "../../../spec_helper"

# Test helper to access private parse_next_link
class GithubClientTestHelper < Shards::Audit::GithubClient
  def test_parse_next_link(header : String?) : String?
    parse_next_link(header)
  end
end

describe Shards::Audit::GithubClient do

  describe "advisory response parsing" do
    it "parses GitHub advisory JSON" do
      body = File.read(File.join(FIXTURES_PATH, "github_advisory_response.json"))
      data = JSON.parse(body)
      advisories = data.as_a

      advisories.size.should eq(1)

      advisory = advisories[0]
      advisory["ghsa_id"].as_s.should eq("GHSA-aaaa-bbbb-cccc")
      advisory["cve_id"].as_s.should eq("CVE-2024-99999")
      advisory["severity"].as_s.should eq("high")

      cvss_score = advisory["cvss"]["score"].as_f
      cvss_score.should eq(7.5)

      fixed = advisory["vulnerabilities"].as_a[0]["first_patched_version"]["identifier"].as_s
      fixed.should eq("1.2.0")
    end
  end

  describe "advisory URL extraction" do
    it "extracts html_url from advisory" do
      body = File.read(File.join(FIXTURES_PATH, "github_advisory_response.json"))
      data = JSON.parse(body)
      advisory = data.as_a[0]
      advisory["html_url"].as_s.should eq("https://github.com/advisories/GHSA-aaaa-bbbb-cccc")
    end
  end

  describe "advisory response edge cases" do
    it "handles advisory with no cve_id" do
      json = %([{
        "ghsa_id": "GHSA-no-cve",
        "summary": "No CVE assigned",
        "severity": "medium",
        "cvss": {"score": 5.0},
        "vulnerabilities": []
      }])
      data = JSON.parse(json)
      advisory = data.as_a[0]
      advisory["cve_id"]?.should be_nil
    end

    it "handles advisory with no CVSS section" do
      json = %([{
        "ghsa_id": "GHSA-no-cvss",
        "summary": "No CVSS",
        "severity": "low",
        "vulnerabilities": []
      }])
      data = JSON.parse(json)
      advisory = data.as_a[0]
      advisory["cvss"]?.should be_nil
      Shards::Audit::Severity.from_string(advisory["severity"].as_s).should eq(Shards::Audit::Severity::Low)
    end

    it "handles advisory with no patched version" do
      json = %([{
        "ghsa_id": "GHSA-no-patch",
        "summary": "No patch available",
        "severity": "high",
        "cvss": {"score": 8.0},
        "vulnerabilities": [{"vulnerable_version_range": "< 99.0"}]
      }])
      data = JSON.parse(json)
      vuln = data.as_a[0]["vulnerabilities"].as_a[0]
      vuln["first_patched_version"]?.should be_nil
    end

    it "handles empty advisory array" do
      json = "[]"
      data = JSON.parse(json)
      data.as_a.should be_empty
    end

    it "handles advisory with no html_url" do
      json = %([{
        "ghsa_id": "GHSA-no-url",
        "summary": "No URL",
        "severity": "medium"
      }])
      data = JSON.parse(json)
      data.as_a[0]["html_url"]?.should be_nil
    end
  end

  describe "initialization" do
    it "creates client without token" do
      client = Shards::Audit::GithubClient.new
      client.should_not be_nil
    end

    it "creates client with token" do
      client = Shards::Audit::GithubClient.new(token: "ghp_test123")
      client.should_not be_nil
    end

    it "creates client with cache" do
      tmp_dir = File.tempname("shards-audit-test")
      cache = Shards::Audit::Cache.new(tmp_dir)
      client = Shards::Audit::GithubClient.new(cache: cache)
      client.should_not be_nil
      FileUtils.rm_rf(tmp_dir) if Dir.exists?(tmp_dir)
    end
  end

  describe "dependency filtering" do
    it "only processes GitHub dependencies" do
      deps = [
        Shards::Audit::Dependency.new(
          name: "kemal",
          git_url: "https://github.com/kemalcr/kemal.git",
          version: "1.1.2"
        ),
        Shards::Audit::Dependency.new(
          name: "gitlab-shard",
          git_url: "https://gitlab.com/user/shard.git",
          version: "0.1.0"
        ),
      ]

      github_deps = deps.select(&.github?)
      github_deps.size.should eq(1)
      github_deps[0].name.should eq("kemal")
    end
  end

  describe "scan with non-GitHub dependencies only" do
    it "returns empty array" do
      client = Shards::Audit::GithubClient.new
      deps = [
        Shards::Audit::Dependency.new(
          name: "gitlab-shard",
          git_url: "https://gitlab.com/user/shard.git",
          version: "0.1.0"
        ),
      ]
      result = client.scan(deps)
      result.should be_empty
    end
  end

  describe "scan with empty dependencies" do
    it "returns empty array" do
      client = Shards::Audit::GithubClient.new
      result = client.scan([] of Shards::Audit::Dependency)
      result.should be_empty
    end
  end

  describe "parse_next_link" do
    it "extracts next URL from Link header" do
      helper = GithubClientTestHelper.new
      header = %(<https://api.github.com/advisories?page=2&per_page=100>; rel="next", <https://api.github.com/advisories?page=5&per_page=100>; rel="last")
      result = helper.test_parse_next_link(header)
      result.should eq("/advisories?page=2&per_page=100")
    end

    it "returns nil when no next link" do
      helper = GithubClientTestHelper.new
      header = %(<https://api.github.com/advisories?page=5&per_page=100>; rel="last")
      result = helper.test_parse_next_link(header)
      result.should be_nil
    end

    it "returns nil for nil header" do
      helper = GithubClientTestHelper.new
      result = helper.test_parse_next_link(nil)
      result.should be_nil
    end

    it "handles URL without query string" do
      helper = GithubClientTestHelper.new
      header = %(<https://api.github.com/advisories>; rel="next")
      result = helper.test_parse_next_link(header)
      result.should eq("/advisories")
    end
  end
end
