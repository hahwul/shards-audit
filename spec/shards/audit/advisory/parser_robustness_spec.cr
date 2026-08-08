require "../../../spec_helper"

# Test doubles exposing the parser modules' private entry points.
private class GithubParserProbe
  include Shards::Audit::GithubParser

  def parse(body : String, dep_name : String = "dep")
    parse_advisories(body, dep_name)
  end
end

private class OsvParserProbe
  include Shards::Audit::OsvParser

  def parse(body : String)
    parse_vulnerability(body)
  end
end

describe Shards::Audit::GithubParser do
  describe "malformed and null fields" do
    # Each of these raised out of a spawned fiber, which then never sent on
    # its channel and deadlocked the scan.
    it "tolerates a null cve_id" do
      body = %([{"ghsa_id":"GHSA-1","summary":"s","severity":"high","cve_id":null}])
      vulns = GithubParserProbe.new.parse(body)
      vulns.size.should eq(1)
      vulns[0].aliases.should be_empty
    end

    it "tolerates a null vulnerabilities array" do
      body = %([{"ghsa_id":"GHSA-1","summary":"s","severity":"high","vulnerabilities":null}])
      vulns = GithubParserProbe.new.parse(body)
      vulns.size.should eq(1)
      vulns[0].fixed_version.should be_nil
    end

    it "tolerates a null summary and cvss block" do
      body = %([{"ghsa_id":"GHSA-1","summary":null,"cvss":null,"severity":"low"}])
      vulns = GithubParserProbe.new.parse(body)
      vulns.size.should eq(1)
      vulns[0].summary.should eq("")
      vulns[0].severity.should eq(Shards::Audit::Severity::Low)
    end

    it "skips an advisory whose ghsa_id is not a string" do
      body = %([{"ghsa_id":123,"summary":"s"},{"ghsa_id":"GHSA-2","summary":"s"}])
      GithubParserProbe.new.parse(body).map(&.id).should eq(["GHSA-2"])
    end

    it "returns empty for a non-array payload" do
      GithubParserProbe.new.parse(%({"message":"Not Found"})).should be_empty
    end
  end

  describe "first_patched_version shapes" do
    it "accepts the REST string form" do
      body = %([{"ghsa_id":"GHSA-1","vulnerabilities":[{"first_patched_version":"1.2.3"}]}])
      GithubParserProbe.new.parse(body)[0].fixed_version.should eq("1.2.3")
    end

    it "accepts the GraphQL object form" do
      body = %([{"ghsa_id":"GHSA-1","vulnerabilities":[{"first_patched_version":{"identifier":"1.2.3"}}]}])
      GithubParserProbe.new.parse(body)[0].fixed_version.should eq("1.2.3")
    end

    it "ignores an unusable shape without raising" do
      body = %([{"ghsa_id":"GHSA-1","vulnerabilities":[{"first_patched_version":[1,2]}]}])
      GithubParserProbe.new.parse(body)[0].fixed_version.should be_nil
    end
  end

  describe "severity resolution" do
    it "prefers the numeric cvss score" do
      body = %([{"ghsa_id":"GHSA-1","cvss":{"score":9.8},"severity":"low"}])
      vuln = GithubParserProbe.new.parse(body)[0]
      vuln.cvss_score.should eq(9.8)
      vuln.severity.should eq(Shards::Audit::Severity::Critical)
    end

    it "falls back to scoring the vector when score is null" do
      body = %([{"ghsa_id":"GHSA-1","cvss":{"score":null,"vector_string":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}])
      vuln = GithubParserProbe.new.parse(body)[0]
      vuln.cvss_score.should eq(9.8)
      vuln.severity.should eq(Shards::Audit::Severity::Critical)
    end
  end
end

describe Shards::Audit::OsvParser do
  describe "malformed and null fields" do
    it "tolerates a null summary" do
      OsvParserProbe.new.parse(%({"id":"OSV-1","summary":null})).not_nil!.summary.should eq("")
    end

    it "falls back to details when summary is absent" do
      vuln = OsvParserProbe.new.parse(%({"id":"OSV-1","details":"long text"}))
      vuln.not_nil!.summary.should eq("long text")
    end

    it "tolerates database_specific being a scalar" do
      vuln = OsvParserProbe.new.parse(%({"id":"OSV-1","database_specific":"oops"}))
      vuln.not_nil!.severity.should eq(Shards::Audit::Severity::Unknown)
    end

    it "tolerates severity entries of the wrong shape" do
      vuln = OsvParserProbe.new.parse(%({"id":"OSV-1","severity":"high"}))
      vuln.not_nil!.severity.should eq(Shards::Audit::Severity::Unknown)
    end

    it "returns nil when the id is missing" do
      OsvParserProbe.new.parse(%({"summary":"no id"})).should be_nil
    end

    it "skips non-string aliases" do
      vuln = OsvParserProbe.new.parse(%({"id":"OSV-1","aliases":["CVE-1",null,7]}))
      vuln.not_nil!.aliases.should eq(["CVE-1"])
    end
  end

  describe "range typing" do
    # A GIT range's events are commit hashes. Parsed as SemVer they yield
    # nil bounds, and a nil-bounded range matches every version, so version
    # filtering silently became a no-op.
    it "ignores GIT ranges when computing affected versions" do
      body = %({
        "id":"OSV-1",
        "affected":[{"ranges":[
          {"type":"GIT","repo":"https://github.com/o/r","events":[{"introduced":"0"},{"fixed":"8b1a9953c4611296a827abf8c47804d7"}]},
          {"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.2.0"}]}
        ]}]
      })
      vuln = OsvParserProbe.new.parse(body).not_nil!
      vuln.affected_ranges.size.should eq(1)
      vuln.affected?("1.1.0").should be_true
      vuln.affected?("2.0.0").should be_false
      vuln.fixed_version.should eq("1.2.0")
    end

    it "never reports a commit hash as the fixed version" do
      body = %({
        "id":"OSV-1",
        "affected":[{"ranges":[
          {"type":"GIT","events":[{"introduced":"0"},{"fixed":"8b1a9953c4611296a827abf8c47804d7"}]}
        ]}]
      })
      vuln = OsvParserProbe.new.parse(body).not_nil!
      vuln.fixed_version.should be_nil
      # With no usable range at all we stay conservative and report.
      vuln.affected_ranges.should be_empty
      vuln.affected?("2.0.0").should be_true
    end

    it "treats an absent range type as SEMVER" do
      body = %({"id":"OSV-1","affected":[{"ranges":[{"events":[{"introduced":"1.0.0"},{"fixed":"1.2.0"}]}]}]})
      vuln = OsvParserProbe.new.parse(body).not_nil!
      vuln.affected?("2.0.0").should be_false
    end

    it "handles ECOSYSTEM ranges" do
      body = %({"id":"OSV-1","affected":[{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.2.0"}]}]}]})
      OsvParserProbe.new.parse(body).not_nil!.affected?("1.5.0").should be_false
    end
  end

  describe "advisory URL" do
    it "skips a non-https reference and keeps the canonical fallback" do
      body = %({"id":"OSV-1","references":[{"type":"ADVISORY","url":"http://insecure.example/a"}]})
      OsvParserProbe.new.parse(body).not_nil!.url.should eq("https://osv.dev/vulnerability/OSV-1")
    end

    it "uses an https advisory reference when present" do
      body = %({"id":"OSV-1","references":[{"type":"ADVISORY","url":"https://example.com/a"}]})
      OsvParserProbe.new.parse(body).not_nil!.url.should eq("https://example.com/a")
    end

    it "tolerates references of the wrong shape" do
      body = %({"id":"OSV-1","references":"nope"})
      OsvParserProbe.new.parse(body).not_nil!.url.should eq("https://osv.dev/vulnerability/OSV-1")
    end
  end

  describe "severity preference" do
    it "prefers the CVSS v3.1 vector over v3.0 regardless of order" do
      body = %({"id":"OSV-1","severity":[
        {"type":"CVSS_V3","score":"CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
        {"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
      ]})
      OsvParserProbe.new.parse(body).not_nil!.cvss_score.should eq(9.8)
    end

    it "leaves a CVSS v4 vector unscored so it falls back to the feed severity" do
      body = %({"id":"OSV-1",
        "severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
        "database_specific":{"severity":"CRITICAL"}})
      vuln = OsvParserProbe.new.parse(body).not_nil!
      vuln.cvss_score.should be_nil
      vuln.severity.should eq(Shards::Audit::Severity::Critical)
    end
  end
end
