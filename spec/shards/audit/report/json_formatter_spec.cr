require "../../../spec_helper"

describe Shards::Audit::JsonFormatter do
  describe "#format" do
    it "outputs valid JSON with tool_version and timestamp for clean result" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 5

      io = IO::Memory.new
      formatter = Shards::Audit::JsonFormatter.new
      formatter.format(result, io)

      data = JSON.parse(io.to_s)
      data["tool_version"].as_s.should eq(Shards::Audit::VERSION)
      data["timestamp"].as_s.should_not be_empty
      # Verify RFC3339 format
      Time.parse_rfc3339(data["timestamp"].as_s).should_not be_nil
      data["dependencies_scanned"].as_i.should eq(5)
      data["vulnerabilities_found"].as_i.should eq(0)
      data["vulnerabilities"].as_a.should be_empty
      data["errors"].as_a.should be_empty
    end

    it "outputs vulnerability details with url as JSON" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 3
      result.vulnerabilities_found = 1
      result.vulnerabilities = [
        Shards::Audit::Vulnerability.new(
          id: "GHSA-xxxx-yyyy-zzzz",
          aliases: ["CVE-2024-12345"],
          summary: "Test vulnerability",
          severity: Shards::Audit::Severity::High,
          cvss_score: 7.5,
          fixed_version: "1.2.0",
          dependency_name: "kemal",
          source: "OSV",
          url: "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz"
        ),
      ]

      io = IO::Memory.new
      formatter = Shards::Audit::JsonFormatter.new
      formatter.format(result, io)

      data = JSON.parse(io.to_s)
      data["tool_version"].as_s.should eq(Shards::Audit::VERSION)
      data["timestamp"].as_s.should_not be_empty
      data["vulnerabilities_found"].as_i.should eq(1)

      vuln = data["vulnerabilities"].as_a[0]
      vuln["id"].as_s.should eq("GHSA-xxxx-yyyy-zzzz")
      vuln["aliases"].as_a.map(&.as_s).should eq(["CVE-2024-12345"])
      vuln["severity"].as_s.should eq("HIGH")
      vuln["cvss_score"].as_f.should eq(7.5)
      vuln["fixed_version"].as_s.should eq("1.2.0")
      vuln["dependency_name"].as_s.should eq("kemal")
      vuln["source"].as_s.should eq("OSV")
      vuln["url"].as_s.should eq("https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz")
    end

    it "includes affected_ranges in output" do
      range = Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.new(1, 0, 0),
        fixed: Shards::Audit::Semver.new(1, 5, 0)
      )
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 1
      result.vulnerabilities_found = 1
      result.vulnerabilities = [
        Shards::Audit::Vulnerability.new(
          id: "GHSA-range",
          dependency_name: "kemal",
          source: "OSV",
          affected_ranges: [range]
        ),
      ]

      io = IO::Memory.new
      formatter = Shards::Audit::JsonFormatter.new
      formatter.format(result, io)

      data = JSON.parse(io.to_s)
      ranges = data["vulnerabilities"].as_a[0]["affected_ranges"].as_a
      ranges.size.should eq(1)
      ranges[0]["introduced"].as_s.should eq("1.0.0")
      ranges[0]["fixed"].as_s.should eq("1.5.0")
    end

    it "handles empty affected_ranges" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 1
      result.vulnerabilities_found = 1
      result.vulnerabilities = [
        Shards::Audit::Vulnerability.new(
          id: "GHSA-no-range",
          dependency_name: "kemal",
          source: "OSV"
        ),
      ]

      io = IO::Memory.new
      formatter = Shards::Audit::JsonFormatter.new
      formatter.format(result, io)

      data = JSON.parse(io.to_s)
      data["vulnerabilities"].as_a[0]["affected_ranges"].as_a.should be_empty
    end

    it "handles nil url, cvss_score, and fixed_version" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 1
      result.vulnerabilities_found = 1
      result.vulnerabilities = [
        Shards::Audit::Vulnerability.new(
          id: "GHSA-minimal",
          severity: Shards::Audit::Severity::Medium,
          dependency_name: "some-shard",
          source: "OSV"
        ),
      ]

      io = IO::Memory.new
      formatter = Shards::Audit::JsonFormatter.new
      formatter.format(result, io)

      data = JSON.parse(io.to_s)
      vuln = data["vulnerabilities"].as_a[0]
      vuln["url"].raw.should be_nil
      vuln["cvss_score"].raw.should be_nil
      vuln["fixed_version"].raw.should be_nil
      vuln["summary"].as_s.should eq("")
      vuln["aliases"].as_a.should be_empty
    end

    it "handles multiple vulnerabilities" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 5
      result.vulnerabilities_found = 2
      result.vulnerabilities = [
        Shards::Audit::Vulnerability.new(
          id: "GHSA-1111",
          severity: Shards::Audit::Severity::Critical,
          dependency_name: "kemal",
          source: "OSV"
        ),
        Shards::Audit::Vulnerability.new(
          id: "GHSA-2222",
          aliases: ["CVE-2024-999"],
          severity: Shards::Audit::Severity::Low,
          dependency_name: "amber",
          source: "GitHub",
          url: "https://github.com/advisories/GHSA-2222"
        ),
      ]

      io = IO::Memory.new
      formatter = Shards::Audit::JsonFormatter.new
      formatter.format(result, io)

      data = JSON.parse(io.to_s)
      data["vulnerabilities"].as_a.size.should eq(2)
      data["vulnerabilities"].as_a[0]["id"].as_s.should eq("GHSA-1111")
      data["vulnerabilities"].as_a[1]["id"].as_s.should eq("GHSA-2222")
      data["vulnerabilities"].as_a[1]["url"].as_s.should eq("https://github.com/advisories/GHSA-2222")
    end

    it "includes errors in output" do
      result = Shards::Audit::AuditResult.new
      result.errors = ["OSV scan failed: timeout"]

      io = IO::Memory.new
      formatter = Shards::Audit::JsonFormatter.new
      formatter.format(result, io)

      data = JSON.parse(io.to_s)
      data["errors"].as_a.map(&.as_s).should eq(["OSV scan failed: timeout"])
    end

    it "includes ignored_count and filtered_count" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 5
      result.ignored_count = 2
      result.filtered_count = 1

      io = IO::Memory.new
      formatter = Shards::Audit::JsonFormatter.new
      formatter.format(result, io)

      data = JSON.parse(io.to_s)
      data["ignored_count"].as_i.should eq(2)
      data["filtered_count"].as_i.should eq(1)
    end
  end
end
