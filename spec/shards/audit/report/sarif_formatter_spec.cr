require "../../../spec_helper"

describe Shards::Audit::SarifFormatter do
  describe "#format" do
    it "outputs valid SARIF JSON for clean result" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 5

      io = IO::Memory.new
      formatter = Shards::Audit::SarifFormatter.new
      formatter.format(result, io)

      data = JSON.parse(io.to_s)
      data["version"].as_s.should eq("2.1.0")
      data["$schema"].as_s.should_not be_empty

      runs = data["runs"].as_a
      runs.size.should eq(1)

      run = runs[0]
      run["tool"]["driver"]["name"].as_s.should eq("shards-audit")
      run["tool"]["driver"]["version"].as_s.should eq(Shards::Audit::VERSION)
      run["tool"]["driver"]["informationUri"].as_s.should eq("https://github.com/hahwul/shards-audit")
      results = run["results"]?.try(&.as_a) || [] of JSON::Any
      results.should be_empty
    end

    it "outputs vulnerability as SARIF result with rule" do
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
      formatter = Shards::Audit::SarifFormatter.new
      formatter.format(result, io)

      data = JSON.parse(io.to_s)
      run = data["runs"].as_a[0]

      # Check rule
      rules = run["tool"]["driver"]["rules"].as_a
      rules.size.should eq(1)
      rule = rules[0]
      rule["id"].as_s.should eq("GHSA-xxxx-yyyy-zzzz")
      rule["shortDescription"]["text"].as_s.should eq("Test vulnerability")
      rule["helpUri"].as_s.should eq("https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz")

      # Check result
      results = run["results"].as_a
      results.size.should eq(1)
      sarif_result = results[0]
      sarif_result["ruleId"].as_s.should eq("GHSA-xxxx-yyyy-zzzz")
      sarif_result["level"].as_s.should eq("error")
      sarif_result["message"]["text"].as_s.should contain("kemal")
      sarif_result["message"]["text"].as_s.should contain("HIGH")
      sarif_result["message"]["text"].as_s.should contain("CVE-2024-12345")
      sarif_result["message"]["text"].as_s.should contain(">= 1.2.0")
    end

    it "maps severity to SARIF level correctly" do
      vulns = {
        Shards::Audit::Severity::Critical => "error",
        Shards::Audit::Severity::High     => "error",
        Shards::Audit::Severity::Medium   => "warning",
        Shards::Audit::Severity::Low      => "note",
        Shards::Audit::Severity::Unknown  => "note",
      }

      vulns.each do |severity, expected_level|
        result = Shards::Audit::AuditResult.new
        result.vulnerabilities_found = 1
        result.vulnerabilities = [
          Shards::Audit::Vulnerability.new(
            id: "GHSA-test-#{severity.label.downcase}",
            severity: severity,
            dependency_name: "test",
            source: "OSV"
          ),
        ]

        io = IO::Memory.new
        Shards::Audit::SarifFormatter.new.format(result, io)

        data = JSON.parse(io.to_s)
        sarif_result = data["runs"].as_a[0]["results"].as_a[0]
        sarif_result["level"].as_s.should eq(expected_level)
      end
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
          severity: Shards::Audit::Severity::Low,
          dependency_name: "amber",
          source: "GitHub"
        ),
      ]

      io = IO::Memory.new
      Shards::Audit::SarifFormatter.new.format(result, io)

      data = JSON.parse(io.to_s)
      run = data["runs"].as_a[0]
      run["tool"]["driver"]["rules"].as_a.size.should eq(2)
      run["results"].as_a.size.should eq(2)
    end

    it "emits a single rule per advisory id when it affects multiple dependencies" do
      result = Shards::Audit::AuditResult.new
      result.dependencies_scanned = 5
      result.vulnerabilities_found = 2
      # Same advisory id affecting two different dependencies.
      result.vulnerabilities = [
        Shards::Audit::Vulnerability.new(
          id: "GHSA-dup-1234",
          severity: Shards::Audit::Severity::High,
          dependency_name: "kemal",
          source: "OSV"
        ),
        Shards::Audit::Vulnerability.new(
          id: "GHSA-dup-1234",
          severity: Shards::Audit::Severity::High,
          dependency_name: "amber",
          source: "OSV"
        ),
      ]

      io = IO::Memory.new
      Shards::Audit::SarifFormatter.new.format(result, io)

      data = JSON.parse(io.to_s)
      run = data["runs"].as_a[0]

      # Only one reportingDescriptor for the shared advisory id (SARIF §3.49.3).
      rules = run["tool"]["driver"]["rules"].as_a
      rules.size.should eq(1)
      rules.map(&.["id"].as_s).should eq(["GHSA-dup-1234"])

      # Both results are still emitted and reference the ruleId.
      results = run["results"].as_a
      results.size.should eq(2)
      results.map(&.["ruleId"].as_s).should eq(["GHSA-dup-1234", "GHSA-dup-1234"])
    end

    it "includes fingerprints on results" do
      result = Shards::Audit::AuditResult.new
      result.vulnerabilities_found = 1
      result.vulnerabilities = [
        Shards::Audit::Vulnerability.new(
          id: "GHSA-fp-test",
          severity: Shards::Audit::Severity::Medium,
          dependency_name: "my-shard",
          source: "OSV"
        ),
      ]

      io = IO::Memory.new
      Shards::Audit::SarifFormatter.new.format(result, io)

      data = JSON.parse(io.to_s)
      sarif_result = data["runs"].as_a[0]["results"].as_a[0]
      sarif_result["fingerprints"]["vulnerabilityId"].as_s.should eq("GHSA-fp-test")
      sarif_result["partialFingerprints"]["dependencyName"].as_s.should eq("my-shard")
    end
  end
end
