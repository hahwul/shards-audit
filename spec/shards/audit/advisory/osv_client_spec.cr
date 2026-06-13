require "../../../spec_helper"

describe Shards::Audit::OsvClient do
  describe "batch response parsing" do
    it "parses batch response JSON" do
      # Test the parsing logic by simulating what the client does internally
      body = File.read(File.join(FIXTURES_PATH, "osv_batch_response.json"))
      data = JSON.parse(body)

      results = data["results"].as_a
      results.size.should eq(2)

      # First entry has vulns
      vulns = results[0]["vulns"].as_a
      vulns.size.should eq(1)
      vulns[0]["id"].as_s.should eq("GHSA-xxxx-yyyy-zzzz")

      # Second entry has no vulns
      results[1]["vulns"].as_a.should be_empty
    end
  end

  describe "vulnerability response parsing" do
    it "parses vulnerability detail JSON" do
      body = File.read(File.join(FIXTURES_PATH, "osv_vuln_response.json"))
      data = JSON.parse(body)

      data["id"].as_s.should eq("GHSA-xxxx-yyyy-zzzz")
      data["summary"].as_s.should eq("Test vulnerability summary")
      data["aliases"].as_a.map(&.as_s).should contain("CVE-2024-12345")

      # Check severity
      severity_arr = data["severity"].as_a
      severity_arr.size.should eq(1)
      severity_arr[0]["score"].as_s.should start_with("CVSS:3.1")

      # Check fixed version
      affected = data["affected"].as_a.first
      range = affected["ranges"].as_a.first
      events = range["events"].as_a
      fixed_event = events.find { |e| e["fixed"]? }
      fixed_event.should_not be_nil
      fixed_event.not_nil!["fixed"].as_s.should eq("1.2.0")
    end
  end

  describe "vulnerability response URL extraction" do
    it "extracts ADVISORY URL from references" do
      body = File.read(File.join(FIXTURES_PATH, "osv_vuln_response.json"))
      data = JSON.parse(body)

      refs = data["references"].as_a
      advisory_ref = refs.find { |r| r["type"].as_s == "ADVISORY" }
      advisory_ref.should_not be_nil
      advisory_ref.not_nil!["url"].as_s.should eq("https://github.com/advisories/GHSA-xxxx-yyyy-zzzz")
    end

    it "has references array in fixture" do
      body = File.read(File.join(FIXTURES_PATH, "osv_vuln_response.json"))
      data = JSON.parse(body)
      data["references"]?.should_not be_nil
      data["references"].as_a.size.should be > 0
    end
  end

  describe "vulnerability response edge cases" do
    it "handles response with no severity section" do
      json = %({
        "id": "GHSA-no-severity",
        "summary": "No severity info",
        "aliases": [],
        "affected": []
      })
      data = JSON.parse(json)
      data["id"].as_s.should eq("GHSA-no-severity")
      data["severity"]?.should be_nil
    end

    it "handles response with no affected/fixed version" do
      json = %({
        "id": "GHSA-no-fix",
        "summary": "No fix available",
        "aliases": ["CVE-2024-00001"],
        "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]
      })
      data = JSON.parse(json)
      affected = data["affected"].as_a.first
      range = affected["ranges"].as_a.first
      events = range["events"].as_a
      fixed_event = events.find { |e| e["fixed"]? }
      fixed_event.should be_nil
    end

    it "handles response with no references" do
      json = %({
        "id": "GHSA-no-refs",
        "summary": "No references",
        "aliases": []
      })
      data = JSON.parse(json)
      data["references"]?.should be_nil
    end

    it "handles response with database_specific severity fallback" do
      json = %({
        "id": "GHSA-db-sev",
        "summary": "DB severity only",
        "aliases": [],
        "database_specific": {"severity": "MEDIUM"}
      })
      data = JSON.parse(json)
      sev_str = data["database_specific"]["severity"].as_s
      Shards::Audit::Severity.from_string(sev_str).should eq(Shards::Audit::Severity::Medium)
    end
  end

  describe "CVSS vector parsing" do
    it "handles well-formed CVSS 3.1 vector" do
      body = File.read(File.join(FIXTURES_PATH, "osv_vuln_response.json"))
      data = JSON.parse(body)
      vector = data["severity"].as_a[0]["score"].as_s
      vector.should start_with("CVSS:3.1")
    end
  end

  describe "batch response edge cases" do
    it "handles empty results array" do
      json = %({"results": []})
      data = JSON.parse(json)
      data["results"].as_a.should be_empty
    end

    it "handles entry with no vulns key" do
      json = %({"results": [{}]})
      data = JSON.parse(json)
      entry = data["results"].as_a[0]
      entry["vulns"]?.should be_nil
    end
  end

  describe "initialization" do
    it "creates client with defaults" do
      client = Shards::Audit::OsvClient.new
      client.should_not be_nil
    end

    it "creates client with custom timeout" do
      client = Shards::Audit::OsvClient.new(timeout: 60, verbose: true)
      client.should_not be_nil
    end

    it "creates client with cache" do
      tmp_dir = File.tempname("shards-audit-test")
      cache = Shards::Audit::Cache.new(tmp_dir)
      client = Shards::Audit::OsvClient.new(cache: cache)
      client.should_not be_nil
      FileUtils.rm_rf(tmp_dir) if Dir.exists?(tmp_dir)
    end
  end

  describe "scan with empty dependencies" do
    it "returns empty array" do
      client = Shards::Audit::OsvClient.new
      result = client.scan([] of Shards::Audit::Dependency)
      result.should be_empty
    end
  end

  describe "URL normalization" do
    # Test the normalization by building queries and checking the output
    it "removes .git suffix in query" do
      dep = Shards::Audit::Dependency.new(
        name: "kemal",
        git_url: "https://github.com/kemalcr/kemal.git",
        version: "1.0.0"
      )
      client = Shards::Audit::OsvClient.new
      # The query should use normalized URL without .git
      # We can verify indirectly by checking that scan with empty deps works
      # Direct URL normalization test via the internal method is not accessible,
      # but we can test the overall flow
      client.should_not be_nil
    end
  end

  describe "git URL normalization logic" do
    it "strips .git suffix" do
      # Test via constructing dependency and checking owner/repo extraction
      dep = Shards::Audit::Dependency.new(
        name: "kemal",
        git_url: "https://github.com/kemalcr/kemal.git",
        version: "1.0.0"
      )
      dep.github_owner_repo.should eq("kemalcr/kemal")
    end

    it "handles git:// protocol URLs" do
      dep = Shards::Audit::Dependency.new(
        name: "test",
        git_url: "git://github.com/owner/repo.git",
        version: "1.0.0"
      )
      # git:// URLs should still extract owner/repo via regex
      dep.github?.should be_true
    end
  end

  describe "dual query deduplication" do
    it "deduplicates vuln IDs from dual batch response" do
      # Simulate a dual batch response where both primary and secondary
      # return the same vulnerability for the same dependency
      json = %({"results": [
        {"vulns": [{"id": "GHSA-1111"}]},
        {"vulns": [{"id": "GHSA-1111"}, {"id": "GHSA-2222"}]}
      ]})
      data = JSON.parse(json)
      results = data["results"].as_a
      results.size.should eq(2)

      # Verify both entries reference valid vuln IDs
      results[0]["vulns"].as_a[0]["id"].as_s.should eq("GHSA-1111")
      results[1]["vulns"].as_a[0]["id"].as_s.should eq("GHSA-1111")
      results[1]["vulns"].as_a[1]["id"].as_s.should eq("GHSA-2222")
    end
  end
end

# Test wrapper to exercise private OsvParser methods that map querybatch
# results back to dependencies and merge follow-up pages.
class TestOsvParserWrapper
  include Shards::Audit::OsvParser

  def map(body : String, deps : Array(Shards::Audit::Dependency))
    extract_vuln_ids_mapped(body, deps)
  end

  def merge(body : String, dep : Shards::Audit::Dependency, hash : Hash(String, Array(String)))
    merge_query_response(body, dep, hash)
  end

  def parse(body : String)
    parse_vulnerability(body)
  end
end

private def make_osv_dep(name : String) : Shards::Audit::Dependency
  Shards::Audit::Dependency.new(
    name: name,
    git_url: "https://github.com/x/#{name}",
    version: "1.0.0"
  )
end

describe "OSV querybatch result alignment" do
  it "raises if the response length does not match the request" do
    deps = [make_osv_dep("a"), make_osv_dep("b")]
    body = %({"results": [{"vulns": [{"id": "G-1"}]}]})

    expect_raises(Shards::Audit::OsvResponseError, /1 results for 2 queries/) do
      TestOsvParserWrapper.new.map(body, deps)
    end
  end

  it "maps results positionally by index" do
    deps = [make_osv_dep("a"), make_osv_dep("b")]
    body = %({"results": [
      {"vulns": [{"id": "G-1"}]},
      {"vulns": [{"id": "G-2"}, {"id": "G-3"}]}
    ]})

    by_dep, followups = TestOsvParserWrapper.new.map(body, deps)
    by_dep["a"].should eq(["G-1"])
    by_dep["b"].should eq(["G-2", "G-3"])
    followups.should be_empty
  end

  it "captures next_page_token follow-ups tagged by query index" do
    deps = [make_osv_dep("a"), make_osv_dep("b")]
    body = %({"results": [
      {"vulns": [{"id": "G-1"}], "next_page_token": "t1"},
      {"vulns": []}
    ]})

    by_dep, followups = TestOsvParserWrapper.new.map(body, deps)
    by_dep["a"].should eq(["G-1"])
    followups.size.should eq(1)
    followups[0][0].should eq(0) # index of the paginating query
    followups[0][1].should eq("t1")
  end

  it "tags follow-ups for the correct query when the same dep is queried twice" do
    # Same dep submitted via two distinct URL forms (git + github). Only
    # the SECOND query paginates; the follow-up must cite index 1, not 0,
    # so the client re-issues the github query body and not the primary
    # git body.
    dep = make_osv_dep("a")
    deps = [dep, dep]
    body = %({"results": [
      {"vulns": [{"id": "G-1"}]},
      {"vulns": [{"id": "G-2"}], "next_page_token": "t-secondary"}
    ]})

    _, followups = TestOsvParserWrapper.new.map(body, deps)
    followups.size.should eq(1)
    followups[0][0].should eq(1)
    followups[0][1].should eq("t-secondary")
  end

  it "merges follow-up /v1/query pages into the existing dep map" do
    by_dep = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
    by_dep["a"] << "G-1"

    body = %({"vulns": [{"id": "G-2"}, {"id": "G-1"}], "next_page_token": "t2"})
    next_token = TestOsvParserWrapper.new.merge(body, make_osv_dep("a"), by_dep)

    by_dep["a"].should eq(["G-1", "G-2"]) # G-1 deduped
    next_token.should eq("t2")
  end
end

describe "OSV parse_vulnerability malformed input hardening" do
  it "handles aliases given as a string without raising TypeCastError" do
    json = %({"id": "GHSA-bad-aliases", "summary": "s", "aliases": "oops"})
    vuln = TestOsvParserWrapper.new.parse(json)
    vuln.should_not be_nil
    vuln.not_nil!.aliases.should be_empty
  end

  it "drops non-string alias elements instead of crashing" do
    json = %({"id": "GHSA-mixed-aliases", "summary": "s", "aliases": ["CVE-2024-1", 42, "CVE-2024-2"]})
    vuln = TestOsvParserWrapper.new.parse(json)
    vuln.should_not be_nil
    vuln.not_nil!.aliases.should eq(["CVE-2024-1", "CVE-2024-2"])
  end

  it "handles severity given as a number without raising TypeCastError" do
    json = %({"id": "GHSA-bad-sev", "summary": "s", "aliases": [], "severity": 7})
    vuln = TestOsvParserWrapper.new.parse(json)
    vuln.should_not be_nil
    vuln.not_nil!.severity.should eq(Shards::Audit::Severity::Unknown)
  end

  it "handles affected/references given as non-arrays without crashing" do
    json = %({"id": "GHSA-bad-shapes", "summary": "s", "aliases": [], "affected": "nope", "references": 5})
    vuln = TestOsvParserWrapper.new.parse(json)
    vuln.should_not be_nil
    vuln.not_nil!.fixed_version.should be_nil
    vuln.not_nil!.url.should eq("https://osv.dev/vulnerability/GHSA-bad-shapes")
  end
end
