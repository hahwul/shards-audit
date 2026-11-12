require "../../../spec_helper"

private class PackageProbe
  include Shards::Audit::GithubParser

  def parse(body : String, dep : String, owner_repo : String? = nil)
    parse_advisories(body, dep, owner_repo)
  end
end

# Trimmed from the live repository advisories of kemalcr/kemal and
# crystal-lang/crystal.
private KEMAL_X97G = %({"ghsa_id":"GHSA-x97g-6h7h-q9w6","severity":"critical",
  "vulnerabilities":[{"package":{"ecosystem":"other","name":"kemal"},
  "vulnerable_version_range":"<= 1.14.0","patched_versions":"1.15.0"}]})
private KEMAL_89XC = %({"ghsa_id":"GHSA-89xc-29wg-6mm5","severity":"high",
  "vulnerabilities":[{"package":{"ecosystem":"crystal","name":"kemalcr/kemal"},
  "vulnerable_version_range":">= 1.10.0, <= 1.14.0","patched_versions":"none"}]})
private CRYSTAL_FJ8W = %({"ghsa_id":"GHSA-fj8w-2r88-5v7w","severity":"medium",
  "vulnerabilities":[{"package":{"ecosystem":"","name":"crystal"},
  "vulnerable_version_range":"<1.21.1","patched_versions":"1.21.1, 1.22.0"}]})

private def one(body : String, dep : String, owner_repo : String?) : Shards::Audit::Vulnerability
  vulns = PackageProbe.new.parse("[#{body}]", dep, owner_repo)
  vulns.size.should eq(1)
  vulns[0]
end

describe "GitHub advisory package matching" do
  it "matches an entry by shard name" do
    vuln = one(KEMAL_X97G, "kemal", "kemalcr/kemal")
    vuln.affected?("1.14.0").should be_true
    vuln.affected?("1.15.0").should be_false
  end

  it "matches an entry by owner/repo, case-insensitively" do
    vuln = one(KEMAL_89XC, "kemal", "KemalCR/Kemal")
    vuln.affected?("1.12.0").should be_true
    vuln.affected?("1.9.0").should be_false
  end

  it "matches an owner/repo name behind a host prefix" do
    body = KEMAL_89XC.sub(%("kemalcr/kemal"), %("https://github.com/kemalcr/kemal"))
    one(body, "kemal", "kemalcr/kemal").affected?("1.9.0").should be_false
    body = KEMAL_89XC.sub(%("kemalcr/kemal"), %("github.com/kemalcr/kemal"))
    one(body, "kemal", "kemalcr/kemal").affected?("1.9.0").should be_false
  end

  it "ignores another package's entry, including its unreadable range" do
    body = %({"ghsa_id":"GHSA-m","vulnerabilities":[
      {"package":{"name":"kemal"},"vulnerable_version_range":"< 1.13.0","patched_versions":"1.13.0"},
      {"package":{"name":"kemal-session"},"vulnerable_version_range":null,"patched_versions":"9.0.0"}]})
    vuln = one(body, "kemal", "kemalcr/kemal")
    vuln.affected?("1.13.0").should be_false
    vuln.affected?("1.12.0").should be_true
    vuln.fixed_version.should eq("1.13.0")
  end

  it "still assumes affected for an applying entry with a null range" do
    body = %({"ghsa_id":"GHSA-n","vulnerabilities":[
      {"package":{"name":"kemal"},"vulnerable_version_range":"< 1.13.0"},
      {"package":{"name":"kemalcr/kemal"},"vulnerable_version_range":null}]})
    one(body, "kemal", "kemalcr/kemal").affected?("9.9.9").should be_true
  end

  it "treats an entry with no package name as applying" do
    body = %({"ghsa_id":"GHSA-p","vulnerabilities":[
      {"package":{"name":"other"},"vulnerable_version_range":"< 1.0.0"},
      {"package":{"ecosystem":"crystal"},"vulnerable_version_range":"< 2.0.0"}]})
    vuln = one(body, "kemal", "kemalcr/kemal")
    vuln.affected?("1.5.0").should be_true
    vuln.affected?("2.0.0").should be_false
  end

  it "keeps every entry when none names the shard" do
    # The repository returned it; judging by all entries is the conservative call.
    vuln = one(CRYSTAL_FJ8W, "crystal-lang", "crystal-lang/crystal")
    vuln.affected?("1.20.0").should be_true
    vuln.affected?("1.21.1").should be_false
  end
end

describe "combined GitHub patched versions" do
  it "names the one fix for the installed window (GHSA-fj8w-2r88-5v7w)" do
    vuln = one(CRYSTAL_FJ8W, "crystal", "crystal-lang/crystal")
    vuln.affected?("1.20.0").should be_true
    vuln.fixed_version_for("1.20.0").should eq("1.21.1")
  end

  it "skips a listed fix that does not leave the window" do
    body = %({"ghsa_id":"GHSA-q","vulnerabilities":[{"package":{"name":"x"},
      "vulnerable_version_range":">= 1.0.0, < 1.3.0","patched_versions":"1.1.0, 1.3.0"}]})
    one(body, "x", nil).fixed_version_for("1.0.5").should eq("1.3.0")
  end

  it "picks per window for a multi-window range" do
    body = %({"ghsa_id":"GHSA-r","vulnerabilities":[{"package":{"name":"x"},
      "vulnerable_version_range":"< 1.21.1, >= 1.22.0, < 1.22.1","patched_versions":"1.21.1, 1.22.1"}]})
    vuln = one(body, "x", nil)
    vuln.fixed_version_for("1.20.0").should eq("1.21.1")
    vuln.fixed_version_for("1.22.0").should eq("1.22.1")
  end

  it "applies to the advisory-level fix when no window names one" do
    vuln = Shards::Audit::Vulnerability.new(id: "X", fixed_version: "1.21.1, 1.22.0")
    vuln.fixed_version_for("1.21.5").should eq("1.22.0")
    vuln.fixed_version_for("1.23.0").should be_nil
  end
end
