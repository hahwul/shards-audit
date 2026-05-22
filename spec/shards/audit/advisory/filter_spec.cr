require "../../../spec_helper"

private def make_filter_vuln(id : String, aliases : Array(String) = [] of String, severity : Shards::Audit::Severity = Shards::Audit::Severity::High, dep : String = "kemal")
  Shards::Audit::Vulnerability.new(
    id: id,
    aliases: aliases,
    summary: "Test vuln #{id}",
    severity: severity,
    dependency_name: dep,
    source: "OSV"
  )
end

describe "Vulnerability filtering" do
  describe "ignore by ID" do
    it "matches primary ID in all_ids" do
      vuln = make_filter_vuln("GHSA-1111-2222-3333")
      (vuln.all_ids & ["GHSA-1111-2222-3333"]).present?.should be_true
    end

    it "matches alias ID in all_ids" do
      vuln = make_filter_vuln("GHSA-1111-2222-3333", aliases: ["CVE-2024-00001"])
      (vuln.all_ids & ["CVE-2024-00001"]).present?.should be_true
    end

    it "does not match unrelated IDs" do
      vuln = make_filter_vuln("GHSA-1111-2222-3333", aliases: ["CVE-2024-00001"])
      (vuln.all_ids & ["GHSA-other"]).present?.should be_false
    end

    it "matches when ignore_ids contains an alias" do
      vuln = make_filter_vuln("GHSA-aaaa", aliases: ["CVE-2024-111", "CVE-2024-222"])
      ignore_ids = ["CVE-2024-222"]
      (vuln.all_ids & ignore_ids).present?.should be_true
    end

    it "handles empty ignore_ids" do
      vuln = make_filter_vuln("GHSA-aaaa")
      (vuln.all_ids & ([] of String)).present?.should be_false
    end
  end

  describe "severity threshold filtering" do
    it "Critical meets all thresholds" do
      critical = Shards::Audit::Severity::Critical
      critical.meets_threshold?(Shards::Audit::Severity::Critical).should be_true
      critical.meets_threshold?(Shards::Audit::Severity::High).should be_true
      critical.meets_threshold?(Shards::Audit::Severity::Medium).should be_true
      critical.meets_threshold?(Shards::Audit::Severity::Low).should be_true
    end

    it "Low only meets Low threshold" do
      low = Shards::Audit::Severity::Low
      low.meets_threshold?(Shards::Audit::Severity::Low).should be_true
      low.meets_threshold?(Shards::Audit::Severity::Medium).should be_false
      low.meets_threshold?(Shards::Audit::Severity::High).should be_false
      low.meets_threshold?(Shards::Audit::Severity::Critical).should be_false
    end

    it "Unknown does not meet any threshold" do
      unknown = Shards::Audit::Severity::Unknown
      unknown.meets_threshold?(Shards::Audit::Severity::Low).should be_false
      unknown.meets_threshold?(Shards::Audit::Severity::Unknown).should be_true
    end
  end

  describe "combined ignore + threshold logic" do
    it "can filter a list by ignore_ids then severity threshold" do
      vulns = [
        make_filter_vuln("GHSA-1111", severity: Shards::Audit::Severity::Critical),
        make_filter_vuln("GHSA-2222", severity: Shards::Audit::Severity::High),
        make_filter_vuln("GHSA-3333", severity: Shards::Audit::Severity::Low),
        make_filter_vuln("GHSA-4444", aliases: ["CVE-2024-999"], severity: Shards::Audit::Severity::Medium),
      ]

      ignore_ids = ["GHSA-2222"]
      threshold = Shards::Audit::Severity::Medium

      # Step 1: ignore by ID
      after_ignore = vulns.reject { |v| (v.all_ids & ignore_ids).present? }
      after_ignore.size.should eq(3)

      # Step 2: filter by threshold
      after_threshold = after_ignore.select(&.severity.meets_threshold?(threshold))
      after_threshold.size.should eq(2) # Critical + Medium
      after_threshold.map(&.id).should contain("GHSA-1111")
      after_threshold.map(&.id).should contain("GHSA-4444")
    end
  end
end
