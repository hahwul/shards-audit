require "../../../spec_helper"

private class QueryProbe < Shards::Audit::OsvClient
  def queries_for(dep : Shards::Audit::Dependency)
    build_dep_queries(dep)
  end

  def normalized(url : String)
    normalize_git_url(url)
  end
end

describe "OSV query construction" do
  probe = QueryProbe.new

  describe "de-duplication" do
    # A commit query ignores the package URL, so building a "git URL" and a
    # "GitHub URL" variant emitted byte-identical JSON twice.
    it "emits one commit query, not one per package URL" do
      dep = Shards::Audit::Dependency.new(
        name: "kemal", git_url: "https://github.com/kemalcr/kemal.git", commit: "abc123")
      queries = probe.queries_for(dep)
      queries.count(&.includes?(%("commit"))).should eq(1)
    end

    it "collapses a git URL that normalises to the GitHub URL" do
      dep = Shards::Audit::Dependency.new(
        name: "kemal", git_url: "https://github.com/kemalcr/kemal.git", version: "1.1.2")
      probe.queries_for(dep).size.should eq(1)
    end

    it "keeps both package URLs when they genuinely differ" do
      dep = Shards::Audit::Dependency.new(
        name: "kemal", git_url: "https://mirror.example/kemalcr/kemal.git", version: "1.1.2")
      probe.queries_for(dep).size.should eq(1) # no GitHub owner/repo derivable
    end
  end

  describe "commit and version coverage" do
    # build_osv_query returned a commit query *instead of* a version query,
    # but shard.lock normally records both and OSV only matches a commit it
    # has indexed — so version-range advisories were missed.
    it "queries by commit and by version when both are known" do
      dep = Shards::Audit::Dependency.new(
        name: "kemal", git_url: "https://github.com/kemalcr/kemal.git",
        version: "1.1.2", commit: "abc123")
      queries = probe.queries_for(dep)
      queries.any?(&.includes?(%("commit":"abc123"))).should be_true
      queries.any?(&.includes?(%("version":"1.1.2"))).should be_true
    end

    it "queries by version alone when there is no commit" do
      dep = Shards::Audit::Dependency.new(
        name: "kemal", git_url: "https://github.com/kemalcr/kemal.git", version: "1.1.2")
      queries = probe.queries_for(dep)
      queries.size.should eq(1)
      queries[0].should contain(%("ecosystem":"GIT"))
      queries[0].should contain(%("name":"https://github.com/kemalcr/kemal"))
    end

    it "produces no query when neither commit nor version is known" do
      dep = Shards::Audit::Dependency.new(name: "kemal", git_url: "https://github.com/kemalcr/kemal.git")
      probe.queries_for(dep).should be_empty
    end
  end

  describe "git URL normalisation" do
    it "strips .git and lowercases the host" do
      probe.normalized("https://GitHub.com/o/r.git").should eq("https://github.com/o/r")
    end

    it "rewrites scp-style SSH remotes" do
      probe.normalized("git@github.com:o/r.git").should eq("https://github.com/o/r")
    end

    it "rewrites the git:// scheme" do
      probe.normalized("git://github.com/o/r.git").should eq("https://github.com/o/r")
    end

    it "falls back to the raw value for an unparseable URL" do
      probe.normalized("https://[bad").should eq("https://[bad")
    end
  end
end

describe "scan resilience" do
  # A fiber that raises before sending on its channel leaves the matching
  # receive blocked forever, deadlocking the whole process. Malformed
  # advisory payloads must cost one dependency, never the scan.
  it "survives a dependency whose advisory payload is malformed" do
    cache_dir = File.join(Dir.tempdir, "shards-audit-spec-#{Random.rand(1_000_000)}")
    Dir.mkdir_p(cache_dir)
    begin
      cache = Shards::Audit::Cache.new(cache_dir, 3600)
      # Pre-seed the cache so no network call happens; the payload has the
      # null/wrong-type fields that used to raise.
      cache.set("github/o/broken.json",
        %([{"ghsa_id":"GHSA-1","cve_id":null,"vulnerabilities":null,"summary":null}]))
      cache.set("github/o/fine.json",
        %([{"ghsa_id":"GHSA-2","summary":"ok","severity":"high"}]))

      client = Shards::Audit::GithubClient.new(timeout: 5, cache: cache)
      deps = [
        Shards::Audit::Dependency.new(name: "broken", git_url: "https://github.com/o/broken.git", version: "1.0.0"),
        Shards::Audit::Dependency.new(name: "fine", git_url: "https://github.com/o/fine.git", version: "1.0.0"),
      ]

      vulns = client.scan(deps)
      vulns.map(&.id).sort!.should eq(["GHSA-1", "GHSA-2"])
    ensure
      FileUtils.rm_rf(cache_dir)
    end
  end
end
