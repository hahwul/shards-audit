require "../../../spec_helper"

describe Shards::Audit::Severity do
  describe ".from_cvss" do
    it "returns Critical for 9.0-10.0" do
      Shards::Audit::Severity.from_cvss(9.0).should eq(Shards::Audit::Severity::Critical)
      Shards::Audit::Severity.from_cvss(10.0).should eq(Shards::Audit::Severity::Critical)
    end

    it "returns High for 7.0-8.9" do
      Shards::Audit::Severity.from_cvss(7.0).should eq(Shards::Audit::Severity::High)
      Shards::Audit::Severity.from_cvss(8.9).should eq(Shards::Audit::Severity::High)
    end

    it "returns Medium for 4.0-6.9" do
      Shards::Audit::Severity.from_cvss(4.0).should eq(Shards::Audit::Severity::Medium)
      Shards::Audit::Severity.from_cvss(6.9).should eq(Shards::Audit::Severity::Medium)
    end

    it "returns Low for 0.1-3.9" do
      Shards::Audit::Severity.from_cvss(0.1).should eq(Shards::Audit::Severity::Low)
      Shards::Audit::Severity.from_cvss(3.9).should eq(Shards::Audit::Severity::Low)
    end

    it "returns Unknown for 0" do
      Shards::Audit::Severity.from_cvss(0.0).should eq(Shards::Audit::Severity::Unknown)
    end

    it "returns Unknown for negative scores" do
      Shards::Audit::Severity.from_cvss(-1.0).should eq(Shards::Audit::Severity::Unknown)
    end

    it "returns Unknown for scores above 10.0" do
      Shards::Audit::Severity.from_cvss(10.1).should eq(Shards::Audit::Severity::Unknown)
    end
  end

  describe ".from_string" do
    it "parses severity strings case-insensitively" do
      Shards::Audit::Severity.from_string("critical").should eq(Shards::Audit::Severity::Critical)
      Shards::Audit::Severity.from_string("HIGH").should eq(Shards::Audit::Severity::High)
      Shards::Audit::Severity.from_string("Medium").should eq(Shards::Audit::Severity::Medium)
      Shards::Audit::Severity.from_string("low").should eq(Shards::Audit::Severity::Low)
    end

    it "treats 'moderate' as Medium" do
      Shards::Audit::Severity.from_string("moderate").should eq(Shards::Audit::Severity::Medium)
    end

    it "returns Unknown for unrecognized values" do
      Shards::Audit::Severity.from_string("none").should eq(Shards::Audit::Severity::Unknown)
      Shards::Audit::Severity.from_string("").should eq(Shards::Audit::Severity::Unknown)
    end
  end

  describe "#label" do
    it "returns uppercase string representation" do
      Shards::Audit::Severity::Critical.label.should eq("CRITICAL")
      Shards::Audit::Severity::High.label.should eq("HIGH")
      Shards::Audit::Severity::Medium.label.should eq("MEDIUM")
      Shards::Audit::Severity::Low.label.should eq("LOW")
      Shards::Audit::Severity::Unknown.label.should eq("UNKNOWN")
    end
  end

  describe "#priority" do
    it "returns priority values in correct order" do
      Shards::Audit::Severity::Critical.priority.should eq(4)
      Shards::Audit::Severity::High.priority.should eq(3)
      Shards::Audit::Severity::Medium.priority.should eq(2)
      Shards::Audit::Severity::Low.priority.should eq(1)
      Shards::Audit::Severity::Unknown.priority.should eq(0)
    end
  end

  describe "#meets_threshold?" do
    it "returns true when severity meets or exceeds threshold" do
      Shards::Audit::Severity::Critical.meets_threshold?(Shards::Audit::Severity::High).should be_true
      Shards::Audit::Severity::High.meets_threshold?(Shards::Audit::Severity::High).should be_true
      Shards::Audit::Severity::Medium.meets_threshold?(Shards::Audit::Severity::Low).should be_true
    end

    it "returns false when severity is below threshold" do
      Shards::Audit::Severity::Medium.meets_threshold?(Shards::Audit::Severity::High).should be_false
      Shards::Audit::Severity::Low.meets_threshold?(Shards::Audit::Severity::Medium).should be_false
      Shards::Audit::Severity::Unknown.meets_threshold?(Shards::Audit::Severity::Low).should be_false
    end
  end

  describe "#color_code" do
    it "returns ANSI color codes" do
      Shards::Audit::Severity::Critical.color_code.should eq("\e[91m")
      Shards::Audit::Severity::High.color_code.should eq("\e[31m")
      Shards::Audit::Severity::Medium.color_code.should eq("\e[33m")
      Shards::Audit::Severity::Low.color_code.should eq("\e[36m")
      Shards::Audit::Severity::Unknown.color_code.should eq("\e[37m")
    end
  end
end
