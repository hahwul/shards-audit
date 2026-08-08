require "../../../spec_helper"

private def result_with(vuln : Shards::Audit::Vulnerability) : Shards::Audit::AuditResult
  result = Shards::Audit::AuditResult.new
  result.dependencies_scanned = 1
  result.vulnerabilities = [vuln]
  result.vulnerabilities_found = 1
  result
end

# An inclusive upper bound, as produced by OSV's `last_affected`.
private def inclusive_bound_vuln : Shards::Audit::Vulnerability
  Shards::Audit::Vulnerability.new(
    id: "OSV-1",
    summary: "example",
    severity: Shards::Audit::Severity::High,
    dependency_name: "dep",
    source: "OSV",
    affected_ranges: [
      Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.parse("1.0.0"),
        fixed: Shards::Audit::Semver.parse("2.0.0"),
        fixed_inclusive: true),
    ]
  )
end

describe "report fidelity for range bounds" do
  # Reports emitted only {introduced, fixed}, so an inclusive upper bound
  # was indistinguishable from an exclusive one and a consumer read the
  # boundary version as safe when it is in fact affected.
  describe Shards::Audit::JsonFormatter do
    it "marks an inclusive upper bound" do
      io = IO::Memory.new
      Shards::Audit::JsonFormatter.new.format(result_with(inclusive_bound_vuln), io)
      range = JSON.parse(io.to_s)["vulnerabilities"][0]["affected_ranges"][0]
      range["fixed"].as_s.should eq("2.0.0")
      range["fixed_inclusive"].as_bool.should be_true
      range["introduced_exclusive"].as_bool.should be_false
      range["constraint"].as_s.should eq(">=1.0.0 <=2.0.0")
    end

    it "emits valid JSON" do
      io = IO::Memory.new
      Shards::Audit::JsonFormatter.new.format(result_with(inclusive_bound_vuln), io)
      JSON.parse(io.to_s)["vulnerabilities_found"].as_i.should eq(1)
    end
  end

  describe Shards::Audit::YamlFormatter do
    it "marks an inclusive upper bound" do
      io = IO::Memory.new
      Shards::Audit::YamlFormatter.new.format(result_with(inclusive_bound_vuln), io)
      range = YAML.parse(io.to_s)["vulnerabilities"][0]["affected_ranges"][0]
      range["fixed_inclusive"].as_bool.should be_true
      range["constraint"].as_s.should eq(">=1.0.0 <=2.0.0")
    end
  end

  describe Shards::Audit::TomlFormatter do
    it "marks an inclusive upper bound" do
      io = IO::Memory.new
      Shards::Audit::TomlFormatter.new.format(result_with(inclusive_bound_vuln), io)
      io.to_s.should contain("fixed_inclusive = true")
      io.to_s.should contain(%(constraint = ">=1.0.0 <=2.0.0"))
    end

    it "escapes control characters that TOML forbids unescaped" do
      vuln = Shards::Audit::Vulnerability.new(
        id: "OSV-1",
        summary: "line one\r\nline two\tand a  control char",
        dependency_name: "dep")
      io = IO::Memory.new
      Shards::Audit::TomlFormatter.new.format(result_with(vuln), io)
      output = io.to_s
      output.should contain("\\r\\n")
      output.should contain("\\t")
      output.should contain("\\u0001")
      # No raw control characters may survive inside the quoted value.
      summary_line = output.lines.find!(&.starts_with?("summary = "))
      summary_line.chars.any?(&.control?).should be_false
    end

    it "escapes quotes and backslashes" do
      vuln = Shards::Audit::Vulnerability.new(
        id: "OSV-1", summary: %(a "quote" and a \\ backslash), dependency_name: "dep")
      io = IO::Memory.new
      Shards::Audit::TomlFormatter.new.format(result_with(vuln), io)
      io.to_s.should contain(%(summary = "a \\"quote\\" and a \\\\ backslash"))
    end
  end
end

describe Shards::Audit::SarifFormatter do
  vuln = Shards::Audit::Vulnerability.new(
    id: "GHSA-1", summary: "s", severity: Shards::Audit::Severity::High,
    dependency_name: "dep", source: "OSV", url: "https://example.com/a")

  # Hardcoding "shard.lock" made GitHub Code Scanning annotate a file that
  # does not exist whenever --path pointed elsewhere, dropping the alerts.
  it "points the location at the audited lockfile" do
    io = IO::Memory.new
    Shards::Audit::SarifFormatter.new("sub/project/shard.lock").format(result_with(vuln), io)
    uri = JSON.parse(io.to_s)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    uri.as_s.should eq("sub/project/shard.lock")
  end

  it "normalises a leading ./" do
    io = IO::Memory.new
    Shards::Audit::SarifFormatter.new("./shard.lock").format(result_with(vuln), io)
    JSON.parse(io.to_s)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
      .as_s.should eq("shard.lock")
  end

  it "makes an in-tree absolute path repository-relative" do
    io = IO::Memory.new
    absolute = File.join(Dir.current, "nested", "shard.lock")
    Shards::Audit::SarifFormatter.new(absolute).format(result_with(vuln), io)
    JSON.parse(io.to_s)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
      .as_s.should eq("nested/shard.lock")
  end

  it "does not leak an out-of-tree absolute path" do
    io = IO::Memory.new
    Shards::Audit::SarifFormatter.new("/somewhere/else/shard.lock").format(result_with(vuln), io)
    JSON.parse(io.to_s)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
      .as_s.should eq("shard.lock")
  end

  it "defaults to shard.lock" do
    io = IO::Memory.new
    Shards::Audit::SarifFormatter.new.format(result_with(vuln), io)
    JSON.parse(io.to_s)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
      .as_s.should eq("shard.lock")
  end
end
