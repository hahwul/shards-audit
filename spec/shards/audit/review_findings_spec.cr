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
