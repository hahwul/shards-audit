require "../../spec_helper"

describe Shards::Audit::Config do
  describe "#initialize" do
    it "creates with defaults" do
      config = Shards::Audit::Config.new

      config.lockfile_path.should eq("./shard.lock")
      config.format.should eq(Shards::Audit::OutputFormat::Table)
      config.verbose.should be_false
      # Colour now defaults to the environment (NO_COLOR / stdout is a tty)
      # rather than always-on, so that piped output stays clean.
      config.no_color.should eq(Shards::Audit::Config.color_disabled_by_environment?)
      config.timeout.should eq(30)
      config.cache_ttl.should eq(86400)
      config.no_cache.should be_false
      config.ignore_ids.should be_empty
      config.severity_threshold.should be_nil
    end

    it "creates with custom values" do
      config = Shards::Audit::Config.new(
        lockfile_path: "/tmp/shard.lock",
        format: Shards::Audit::OutputFormat::Json,
        verbose: true,
        no_color: true,
        timeout: 60,
        cache_ttl: 3600,
        no_cache: true,
        ignore_ids: ["GHSA-xxxx"],
        severity_threshold: Shards::Audit::Severity::High
      )

      config.lockfile_path.should eq("/tmp/shard.lock")
      config.format.should eq(Shards::Audit::OutputFormat::Json)
      config.verbose.should be_true
      config.no_color.should be_true
      config.timeout.should eq(60)
      config.cache_ttl.should eq(3600)
      config.no_cache.should be_true
      config.ignore_ids.should eq(["GHSA-xxxx"])
      config.severity_threshold.should eq(Shards::Audit::Severity::High)
    end
  end

  describe "property mutation" do
    it "allows modifying ignore_ids" do
      config = Shards::Audit::Config.new
      config.ignore_ids << "GHSA-aaaa"
      config.ignore_ids << "GHSA-bbbb"
      config.ignore_ids.should eq(["GHSA-aaaa", "GHSA-bbbb"])
    end

    it "allows setting severity_threshold" do
      config = Shards::Audit::Config.new
      config.severity_threshold = Shards::Audit::Severity::Medium
      config.severity_threshold.should eq(Shards::Audit::Severity::Medium)
    end
  end
end

describe Shards::Audit::AuditResult do
  describe "#initialize" do
    it "creates with zero defaults" do
      result = Shards::Audit::AuditResult.new

      result.dependencies_scanned.should eq(0)
      result.vulnerabilities_found.should eq(0)
      result.vulnerabilities.should be_empty
      result.errors.should be_empty
      result.ignored_count.should eq(0)
      result.filtered_count.should eq(0)
    end
  end

  describe "#clean?" do
    it "returns true when no vulnerabilities" do
      result = Shards::Audit::AuditResult.new
      result.clean?.should be_true
    end

    it "returns false when vulnerabilities exist" do
      result = Shards::Audit::AuditResult.new
      result.vulnerabilities = [
        Shards::Audit::Vulnerability.new(id: "GHSA-test", dependency_name: "kemal"),
      ]
      result.clean?.should be_false
    end

    it "returns true even with errors but no vulns" do
      result = Shards::Audit::AuditResult.new
      result.errors = ["OSV scan failed"]
      result.clean?.should be_true
    end
  end
end

describe Shards::Audit::OutputFormat do
  it "defines Table and Json" do
    Shards::Audit::OutputFormat::Table.should_not be_nil
    Shards::Audit::OutputFormat::Json.should_not be_nil
  end
end
