require "../../../spec_helper"

describe Shards::Audit::Scanner do
  describe "deduplication" do
    it "removes duplicate vulnerabilities by matching IDs" do
      vuln1 = Shards::Audit::Vulnerability.new(
        id: "GHSA-xxxx-yyyy-zzzz",
        aliases: ["CVE-2024-12345"],
        summary: "Test vuln",
        severity: Shards::Audit::Severity::High,
        dependency_name: "kemal",
        source: "OSV"
      )
      vuln2 = Shards::Audit::Vulnerability.new(
        id: "GHSA-xxxx-yyyy-zzzz",
        aliases: ["CVE-2024-12345"],
        summary: "Test vuln",
        severity: Shards::Audit::Severity::High,
        dependency_name: "kemal",
        source: "GitHub"
      )

      vuln1.duplicate_of?(vuln2).should be_true
    end

    it "detects duplicates through aliases" do
      vuln1 = Shards::Audit::Vulnerability.new(
        id: "GHSA-xxxx-yyyy-zzzz",
        aliases: ["CVE-2024-12345"],
        summary: "Test vuln",
        severity: Shards::Audit::Severity::High,
        dependency_name: "kemal",
        source: "OSV"
      )
      vuln2 = Shards::Audit::Vulnerability.new(
        id: "CVE-2024-12345",
        aliases: [] of String,
        summary: "Test vuln",
        severity: Shards::Audit::Severity::High,
        dependency_name: "kemal",
        source: "GitHub"
      )

      vuln1.duplicate_of?(vuln2).should be_true
    end

    it "does not flag different vulnerabilities as duplicates" do
      vuln1 = Shards::Audit::Vulnerability.new(
        id: "GHSA-aaaa-bbbb-cccc",
        aliases: ["CVE-2024-11111"],
        summary: "Vuln 1",
        severity: Shards::Audit::Severity::High,
        dependency_name: "kemal",
        source: "OSV"
      )
      vuln2 = Shards::Audit::Vulnerability.new(
        id: "GHSA-xxxx-yyyy-zzzz",
        aliases: ["CVE-2024-99999"],
        summary: "Vuln 2",
        severity: Shards::Audit::Severity::Medium,
        dependency_name: "kemal",
        source: "GitHub"
      )

      vuln1.duplicate_of?(vuln2).should be_false
    end

    it "does not deduplicate same CVE across different packages" do
      vuln1 = Shards::Audit::Vulnerability.new(
        id: "GHSA-xxxx-yyyy-zzzz",
        aliases: ["CVE-2024-12345"],
        summary: "Vuln in kemal",
        severity: Shards::Audit::Severity::High,
        dependency_name: "kemal",
        source: "OSV"
      )
      vuln2 = Shards::Audit::Vulnerability.new(
        id: "GHSA-xxxx-yyyy-zzzz",
        aliases: ["CVE-2024-12345"],
        summary: "Vuln in amber",
        severity: Shards::Audit::Severity::High,
        dependency_name: "amber",
        source: "OSV"
      )

      vuln1.duplicate_of?(vuln2).should be_false
    end

    it "detects duplicate when one vuln's ID is in other's aliases" do
      vuln1 = Shards::Audit::Vulnerability.new(
        id: "GHSA-aaaa-bbbb-cccc",
        aliases: ["CVE-2024-111"],
        dependency_name: "kemal",
        source: "OSV"
      )
      vuln2 = Shards::Audit::Vulnerability.new(
        id: "GHSA-dddd-eeee-ffff",
        aliases: ["CVE-2024-111", "GHSA-aaaa-bbbb-cccc"],
        dependency_name: "kemal",
        source: "GitHub"
      )

      vuln1.duplicate_of?(vuln2).should be_true
    end

    it "handles both vulns having empty aliases" do
      vuln1 = Shards::Audit::Vulnerability.new(
        id: "GHSA-aaaa",
        dependency_name: "kemal",
        source: "OSV"
      )
      vuln2 = Shards::Audit::Vulnerability.new(
        id: "GHSA-bbbb",
        dependency_name: "kemal",
        source: "GitHub"
      )

      vuln1.duplicate_of?(vuln2).should be_false
    end
  end

  describe "empty dependencies" do
    it "returns clean result for empty dependencies" do
      config = Shards::Audit::Config.new
      scanner = Shards::Audit::Scanner.new(config)
      result = scanner.scan([] of Shards::Audit::Dependency)

      result.clean?.should be_true
      result.dependencies_scanned.should eq(0)
      result.vulnerabilities_found.should eq(0)
    end
  end

  describe "result initialization" do
    it "initializes ignored_count and filtered_count to zero" do
      config = Shards::Audit::Config.new
      scanner = Shards::Audit::Scanner.new(config)
      result = scanner.scan([] of Shards::Audit::Dependency)

      result.ignored_count.should eq(0)
      result.filtered_count.should eq(0)
    end
  end
end
