require "../../spec_helper"

# Regressions found while reviewing the hardening pass itself.

private class OsvProbe
  include Shards::Audit::OsvParser

  def parse(body : String)
    parse_vulnerability(body)
  end
end

private class GithubProbe
  include Shards::Audit::GithubParser

  def parse(body : String, dep : String = "dep")
    parse_advisories(body, dep)
  end
end

describe Shards::Audit::Proxy do
  describe "unsupported proxy schemes" do
    # ALL_PROXY=socks5://... is the standard SOCKS configuration and is often
    # exported globally. We only speak HTTP CONNECT, and pointing CONNECT at
    # a SOCKS listener does not fail fast — it hangs until the read timeout,
    # which is retryable, so every dependency burned four full timeouts.
    it "ignores a socks5 proxy instead of trying to CONNECT to it" do
      Shards::Audit::Proxy.for(URI.parse("https://api.osv.dev"),
        {"ALL_PROXY" => "socks5://127.0.0.1:1080"}).should be_nil
    end

    it "ignores socks5h and socks4" do
      {"socks5h://p:1080", "socks4://p:1080"}.each do |value|
        Shards::Audit::Proxy.for(URI.parse("https://api.osv.dev"), {"ALL_PROXY" => value}).should be_nil
      end
    end

    it "still accepts http and https proxies" do
      Shards::Audit::Proxy.for(URI.parse("https://api.osv.dev"), {"ALL_PROXY" => "http://p:3128"})
        .should_not be_nil
      Shards::Audit::Proxy.for(URI.parse("https://api.osv.dev"), {"ALL_PROXY" => "https://p:3128"})
        .should_not be_nil
    end

    it "still accepts a bare host:port, which means http" do
      Shards::Audit::Proxy.for(URI.parse("https://api.osv.dev"), {"ALL_PROXY" => "p:3128"})
        .try(&.scheme).should eq("http")
    end
  end

  describe "IPv6 entries in NO_PROXY" do
    # URI#host keeps the brackets, but curl and Go's httpproxy both accept a
    # bare `::1`. The naive "last colon is the port" split tore that into
    # host ":" port "1" and the traffic silently went through the proxy.
    it "matches an unbracketed IPv6 literal" do
      Shards::Audit::Proxy.for(URI.parse("https://[::1]"),
        {"HTTPS_PROXY" => "http://p:1", "NO_PROXY" => "::1"}).should be_nil
    end

    it "matches a bracketed IPv6 literal" do
      Shards::Audit::Proxy.for(URI.parse("https://[::1]"),
        {"HTTPS_PROXY" => "http://p:1", "NO_PROXY" => "[::1]"}).should be_nil
    end

    it "matches a bracketed entry carrying a port" do
      env = {"HTTPS_PROXY" => "http://p:1", "NO_PROXY" => "[::1]:8443"}
      Shards::Audit::Proxy.for(URI.parse("https://[::1]:8443"), env).should be_nil
      Shards::Audit::Proxy.for(URI.parse("https://[::1]"), env).should_not be_nil
    end

    it "does not bypass an unrelated IPv6 host" do
      Shards::Audit::Proxy.for(URI.parse("https://[::2]"),
        {"HTTPS_PROXY" => "http://p:1", "NO_PROXY" => "::1"}).should_not be_nil
    end

    it "still handles ordinary host:port entries" do
      env = {"HTTPS_PROXY" => "http://p:1", "NO_PROXY" => "api.osv.dev:8443"}
      Shards::Audit::Proxy.for(URI.parse("https://api.osv.dev:8443"), env).should be_nil
      Shards::Audit::Proxy.for(URI.parse("https://api.osv.dev"), env).should_not be_nil
    end
  end
end

describe Shards::Audit::Dependency do
  describe "owner/repo cannot smuggle request syntax" do
    # The value is interpolated into the advisory request path, and it comes
    # from the lockfile. None of these are valid git remotes, so declining to
    # derive an owner/repo at all is the right answer: the dependency is
    # simply not treated as a GitHub one, and OSV still queries it by URL.
    it "declines a URL carrying a query-parameter separator" do
      dep = Shards::Audit::Dependency.new(
        name: "x", git_url: "https://github.com/owner/repo&affects=torvalds%2Flinux")
      dep.github_owner_repo.should be_nil
    end

    it "declines an embedded NUL byte" do
      dep = Shards::Audit::Dependency.new(name: "x", git_url: "https://github.com/owner/re\u0000po")
      dep.github_owner_repo.should be_nil
    end

    it "declines a percent-encoded path separator" do
      dep = Shards::Audit::Dependency.new(name: "x", git_url: "https://github.com/owner/repo%2F..%2Fevil")
      dep.github_owner_repo.should be_nil
    end

    it "still reads a URL carrying a query string or fragment" do
      Shards::Audit::Dependency.new(name: "x", git_url: "https://github.com/owner/repo?ref=main")
        .github_owner_repo.should eq("owner/repo")
      Shards::Audit::Dependency.new(name: "x", git_url: "https://github.com/owner/repo#tag")
        .github_owner_repo.should eq("owner/repo")
    end

    it "still accepts every character GitHub actually permits" do
      dep = Shards::Audit::Dependency.new(name: "x", git_url: "https://github.com/My-Org_1/some.repo-name_2.cr.git")
      dep.github_owner_repo.should eq("My-Org_1/some.repo-name_2.cr")
    end
  end
end

describe Shards::Audit::OsvParser do
  describe "advisories that mix GIT and ecosystem entries" do
    # We query OSV with `ecosystem: "GIT"`, so the GIT entry is frequently
    # the one OSV matched us on. Judging our version against a *different*
    # package's ecosystem range discarded real findings.
    it "does not filter on a foreign ecosystem's range" do
      body = %({"id":"GHSA-mixed","affected":[
        {"package":{"ecosystem":"Go","name":"github.com/o/r"},
         "ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.2.0"}]}]},
        {"package":{"ecosystem":"GIT","name":"https://github.com/o/r"},
         "ranges":[{"type":"GIT","events":[{"introduced":"aaaa"},{"fixed":"bbbb"}]}]}]})
      vuln = OsvProbe.new.parse(body).not_nil!
      vuln.affected_ranges.should be_empty
      vuln.affected?("0.9.0").should be_true
    end

    it "still filters when every entry is version-addressed" do
      body = %({"id":"GHSA-semver","affected":[
        {"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.2.0"}]}]}]})
      vuln = OsvProbe.new.parse(body).not_nil!
      vuln.affected?("0.9.0").should be_false
      vuln.affected?("1.1.0").should be_true
    end

    it "still uses a SEMVER range that sits beside a GIT range in one entry" do
      body = %({"id":"GHSA-both","affected":[
        {"ranges":[
          {"type":"GIT","events":[{"introduced":"0"},{"fixed":"deadbeef"}]},
          {"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.2.0"}]}]}]})
      vuln = OsvProbe.new.parse(body).not_nil!
      vuln.affected_ranges.size.should eq(1)
      vuln.affected?("2.0.0").should be_false
      vuln.fixed_version.should eq("1.2.0")
    end
  end

  describe "fixed version reporting" do
    # Requiring the value to parse as SemVer reported "no fix available" for
    # advisories that named one.
    it "keeps a four-component fixed version" do
      body = %({"id":"OSV-1","affected":[
        {"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3.4"}]}]}]})
      OsvProbe.new.parse(body).not_nil!.fixed_version.should eq("1.2.3.4")
    end

    it "keeps a non-numeric fixed version" do
      body = %({"id":"OSV-1","affected":[
        {"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0.RELEASE"}]}]}]})
      OsvProbe.new.parse(body).not_nil!.fixed_version.should eq("2.0.0.RELEASE")
    end

    it "still refuses a commit hash from a GIT range" do
      body = %({"id":"OSV-1","affected":[
        {"ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"8b1a9953c4611296a827abf8c47804d7"}]}]}]})
      OsvProbe.new.parse(body).not_nil!.fixed_version.should be_nil
    end
  end
end

describe Shards::Audit::Scanner do
  scanner = Shards::Audit::Scanner.new(Shards::Audit::Config.new)

  describe "combining the same advisory from both sources" do
    # OSV is concatenated ahead of GitHub, and dedup kept whichever record
    # came first — so a sparse OSV entry discarded GitHub's severity,
    # summary and fix version for the very same GHSA.
    it "keeps the richer fields from either source" do
      osv = Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "d",
        source: "OSV", severity: Shards::Audit::Severity::Unknown, summary: "")
      github = Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "d",
        source: "GitHub", severity: Shards::Audit::Severity::Critical,
        summary: "Remote code execution", cvss_score: 9.8, fixed_version: "1.2.3")

      merged = scanner.deduplicate([osv, github])
      merged.size.should eq(1)
      merged[0].severity.should eq(Shards::Audit::Severity::Critical)
      merged[0].cvss_score.should eq(9.8)
      merged[0].summary.should eq("Remote code execution")
      merged[0].fixed_version.should eq("1.2.3")
      merged[0].source.should eq("OSV, GitHub")
    end

    it "never downgrades a severity" do
      low = Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "d",
        source: "OSV", severity: Shards::Audit::Severity::Low, cvss_score: 2.0)
      high = Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "d",
        source: "GitHub", severity: Shards::Audit::Severity::High, cvss_score: 8.1)

      scanner.deduplicate([low, high])[0].severity.should eq(Shards::Audit::Severity::High)
      scanner.deduplicate([high, low])[0].severity.should eq(Shards::Audit::Severity::High)
    end

    it "keeps severity and its score consistent" do
      merged = scanner.deduplicate([
        Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "d",
          source: "OSV", severity: Shards::Audit::Severity::Low, cvss_score: 2.0),
        Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "d",
          source: "GitHub", severity: Shards::Audit::Severity::High, cvss_score: 8.1),
      ])
      merged[0].severity.should eq(Shards::Audit::Severity::High)
      merged[0].cvss_score.should eq(8.1)
    end

    it "merges records linked only by an alias" do
      a = Shards::Audit::Vulnerability.new(id: "GHSA-x", aliases: ["CVE-2024-1"],
        dependency_name: "d", severity: Shards::Audit::Severity::High)
      b = Shards::Audit::Vulnerability.new(id: "CVE-2024-1", dependency_name: "d",
        severity: Shards::Audit::Severity::Critical, fixed_version: "2.0.0")

      merged = scanner.deduplicate([a, b])
      merged.size.should eq(1)
      merged[0].severity.should eq(Shards::Audit::Severity::Critical)
      merged[0].fixed_version.should eq("2.0.0")
    end

    it "does not merge across different dependencies" do
      a = Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "one")
      b = Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "two")
      scanner.deduplicate([a, b]).size.should eq(2)
    end

    describe "affected ranges" do
      it "stays conservative when either side could not be evaluated" do
        bounded = Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "d",
          affected_ranges: [Shards::Audit::SemverRange.new(
            introduced: Shards::Audit::Semver.parse("1.0.0"),
            fixed: Shards::Audit::Semver.parse("1.1.0"))])
        unbounded = Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "d")

        merged = scanner.deduplicate([bounded, unbounded])[0]
        merged.affected_ranges.should be_empty
        merged.affected?("9.9.9").should be_true
      end

      it "unions the windows when both sides are evaluable" do
        a = Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "d",
          affected_ranges: [Shards::Audit::SemverRange.new(
            introduced: Shards::Audit::Semver.parse("1.0.0"),
            fixed: Shards::Audit::Semver.parse("1.1.0"))])
        b = Shards::Audit::Vulnerability.new(id: "GHSA-1", dependency_name: "d",
          affected_ranges: [Shards::Audit::SemverRange.new(
            introduced: Shards::Audit::Semver.parse("2.0.0"),
            fixed: Shards::Audit::Semver.parse("2.1.0"))])

        merged = scanner.deduplicate([a, b])[0]
        merged.affected?("1.0.5").should be_true
        merged.affected?("2.0.5").should be_true
        merged.affected?("1.5.0").should be_false
      end
    end
  end
end

describe Shards::Audit::SemverRangeParser do
  describe "GitHub vulnerable_version_range with several windows" do
    # A single introduced/fixed accumulator kept only the last window, so a
    # version inside an earlier one was judged unaffected — a false negative.
    it "keeps every window" do
      ranges = Shards::Audit::SemverRangeParser.parse_github_range(
        ">= 1.0.0, < 1.1.0, >= 2.0.0, < 2.1.0")
      ranges.map(&.to_constraint).should eq([">=1.0.0 <1.1.0", ">=2.0.0 <2.1.0"])
    end

    it "reports a version inside the first window" do
      vuln = Shards::Audit::Vulnerability.new(id: "GHSA-1",
        affected_ranges: Shards::Audit::SemverRangeParser.parse_github_range(
          ">= 1.0.0, < 1.1.0, >= 2.0.0, < 2.1.0"))
      vuln.affected?("1.0.5").should be_true
      vuln.affected?("2.0.5").should be_true
      vuln.affected?("1.5.0").should be_false
      vuln.affected?("3.0.0").should be_false
    end
  end

  describe "constraints written without a space" do
    # `split(/\s+/, 2)` produced one part and the constraint was dropped, so
    # the advisory ended up with no ranges and filtering did nothing.
    it "parses >=1.0.0, <1.2.0" do
      Shards::Audit::SemverRangeParser.parse_github_range(">=1.0.0, <1.2.0")
        .map(&.to_constraint).should eq([">=1.0.0 <1.2.0"])
    end

    it "filters correctly with no-space constraints" do
      vuln = Shards::Audit::Vulnerability.new(id: "GHSA-1",
        affected_ranges: Shards::Audit::SemverRangeParser.parse_github_range(">=1.0.0, <1.2.0"))
      vuln.affected?("1.1.0").should be_true
      vuln.affected?("1.3.0").should be_false
    end
  end

  describe "other constraint shapes" do
    it "treats a bare version as exact" do
      Shards::Audit::SemverRangeParser.parse_github_range("1.2.3")
        .map(&.to_constraint).should eq([">=1.2.3 <=1.2.3"])
    end

    it "handles = and ==" do
      Shards::Audit::SemverRangeParser.parse_github_range("= 1.2.3")
        .map(&.to_constraint).should eq([">=1.2.3 <=1.2.3"])
      Shards::Audit::SemverRangeParser.parse_github_range("== 1.2.3")
        .map(&.to_constraint).should eq([">=1.2.3 <=1.2.3"])
    end

    it "keeps single-sided bounds" do
      Shards::Audit::SemverRangeParser.parse_github_range("< 1.2.0")
        .map(&.to_constraint).should eq(["<1.2.0"])
      Shards::Audit::SemverRangeParser.parse_github_range(">= 1.0.0")
        .map(&.to_constraint).should eq([">=1.0.0"])
      Shards::Audit::SemverRangeParser.parse_github_range("<= 1.2.0")
        .map(&.to_constraint).should eq(["<=1.2.0"])
    end

    it "returns nothing for empty or unparseable input" do
      Shards::Audit::SemverRangeParser.parse_github_range("").should be_empty
      Shards::Audit::SemverRangeParser.parse_github_range("   ").should be_empty
      Shards::Audit::SemverRangeParser.parse_github_range("~> 1.2").should be_empty
    end

    it "keeps a prerelease lower bound" do
      Shards::Audit::SemverRangeParser.parse_github_range(">= 1.0.0-beta, < 1.0.0")
        .map(&.to_constraint).should eq([">=1.0.0-beta <1.0.0"])
    end

    # The advisory says the fix landed in 2.0.0; a release candidate predates
    # it and therefore does not carry the fix.
    it "still reports a release candidate below the fixed version" do
      vuln = Shards::Audit::Vulnerability.new(id: "GHSA-1",
        affected_ranges: Shards::Audit::SemverRangeParser.parse_github_range("< 2.0.0"))
      vuln.affected?("2.0.0-rc1").should be_true
      vuln.affected?("2.0.0").should be_false
    end
  end
end

describe Shards::Audit::GithubParser do
  describe "a zero cvss score" do
    # GitHub ships `"score": 0.0` alongside a real vector for some
    # advisories; 0.0 is truthy in Crystal, so it suppressed the vector.
    it "falls back to the vector when the score is 0.0" do
      body = %([{"ghsa_id":"GHSA-1","cvss":{"score":0.0,
        "vector_string":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}])
      vuln = GithubProbe.new.parse(body)[0]
      vuln.cvss_score.should eq(9.8)
      vuln.severity.should eq(Shards::Audit::Severity::Critical)
    end

    it "leaves the score nil when there is no vector either" do
      GithubProbe.new.parse(%([{"ghsa_id":"GHSA-1","cvss":{"score":0.0}}]))[0]
        .cvss_score.should be_nil
    end
  end
end
