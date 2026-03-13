require "../../../spec_helper"

describe Shards::Audit::TableFormatter do
  describe "#format" do
    it "shows clean message when no vulnerabilities" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 5

      io = IO::Memory.new
      formatter = Shards::Audit::TableFormatter.new(no_color: true)
      formatter.format(result, io)

      output = io.to_s
      output.should contain("No vulnerabilities found!")
      output.should contain("5 dependencies scanned")
    end

    it "shows vulnerability details with CVSS score and URL" do
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
      formatter = Shards::Audit::TableFormatter.new(no_color: true)
      formatter.format(result, io)

      output = io.to_s
      output.should contain("1 vulnerabilities found!")
      output.should contain("HIGH (7.5)")
      output.should contain("GHSA-xxxx-yyyy-zzzz")
      output.should contain("kemal")
      output.should contain("Test vulnerability")
      output.should contain("1.2.0")
      output.should contain("https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz")
      output.should contain("OSV")
      output.should contain("CVE-2024-12345")
    end

    it "shows ignored and filtered counts in summary" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 10
      result.vulnerabilities_found = 2
      result.ignored_count = 1
      result.filtered_count = 3
      result.vulnerabilities = [
        Shards::Audit::Vulnerability.new(
          id: "GHSA-xxxx-yyyy-zzzz",
          severity: Shards::Audit::Severity::Critical,
          dependency_name: "kemal",
          source: "OSV"
        ),
        Shards::Audit::Vulnerability.new(
          id: "GHSA-aaaa-bbbb-cccc",
          severity: Shards::Audit::Severity::High,
          dependency_name: "amber",
          source: "GitHub"
        ),
      ]

      io = IO::Memory.new
      formatter = Shards::Audit::TableFormatter.new(no_color: true)
      formatter.format(result, io)

      output = io.to_s
      output.should contain("1 ignored")
      output.should contain("3 below threshold")
    end

    it "shows vulnerability without CVSS score, URL, fixed_version, or summary" do
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
      formatter = Shards::Audit::TableFormatter.new(no_color: true)
      formatter.format(result, io)

      output = io.to_s
      output.should contain("MEDIUM")
      output.should contain("GHSA-minimal")
      output.should contain("some-shard")
      output.should_not contain("(") # no CVSS score parens
      output.should_not contain("URL:")
      output.should_not contain("Fix:")
      output.should_not contain("Summary:")
      output.should_not contain("Aliases:")
    end

    it "does not show ignored/filtered counts when zero" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 3
      result.vulnerabilities_found = 1
      result.vulnerabilities = [
        Shards::Audit::Vulnerability.new(
          id: "GHSA-xxxx",
          severity: Shards::Audit::Severity::High,
          dependency_name: "kemal",
          source: "OSV"
        ),
      ]

      io = IO::Memory.new
      formatter = Shards::Audit::TableFormatter.new(no_color: true)
      formatter.format(result, io)

      output = io.to_s
      output.should_not contain("ignored")
      output.should_not contain("below threshold")
    end

    it "shows multiple vulnerabilities separated" do
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
          severity: Shards::Audit::Severity::Low,
          dependency_name: "amber",
          source: "GitHub"
        ),
      ]

      io = IO::Memory.new
      formatter = Shards::Audit::TableFormatter.new(no_color: true)
      formatter.format(result, io)

      output = io.to_s
      output.should contain("GHSA-1111")
      output.should contain("GHSA-2222")
      output.should contain("CRITICAL")
      output.should contain("LOW")
      output.should contain("2 vulnerabilities found!")
    end

    it "shows warnings for errors" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 1
      result.errors = ["OSV scan failed: connection refused"]

      io = IO::Memory.new
      formatter = Shards::Audit::TableFormatter.new(no_color: true)
      formatter.format(result, io)

      output = io.to_s
      output.should contain("Warning:")
      output.should contain("OSV scan failed")
    end
  end
end
