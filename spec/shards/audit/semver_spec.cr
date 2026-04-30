require "../../spec_helper"

describe Shards::Audit::Semver do
  describe ".parse" do
    it "parses standard version" do
      v = Shards::Audit::Semver.parse("1.2.3")
      v.should_not be_nil
      v = v.not_nil!
      v.major.should eq(1)
      v.minor.should eq(2)
      v.patch.should eq(3)
      v.prerelease.should be_nil
    end

    it "parses version with v prefix" do
      v = Shards::Audit::Semver.parse("v0.1.0")
      v.should_not be_nil
      v = v.not_nil!
      v.major.should eq(0)
      v.minor.should eq(1)
      v.patch.should eq(0)
    end

    it "parses version with prerelease" do
      v = Shards::Audit::Semver.parse("1.0.0-rc1")
      v.should_not be_nil
      v = v.not_nil!
      v.major.should eq(1)
      v.minor.should eq(0)
      v.patch.should eq(0)
      v.prerelease.should eq("rc1")
    end

    it "parses major.minor only" do
      v = Shards::Audit::Semver.parse("1.2")
      v.should_not be_nil
      v = v.not_nil!
      v.major.should eq(1)
      v.minor.should eq(2)
      v.patch.should eq(0)
    end

    it "parses major only" do
      v = Shards::Audit::Semver.parse("3")
      v.should_not be_nil
      v = v.not_nil!
      v.major.should eq(3)
      v.minor.should eq(0)
      v.patch.should eq(0)
    end

    it "returns nil for empty string" do
      Shards::Audit::Semver.parse("").should be_nil
    end

    it "returns nil for non-numeric" do
      Shards::Audit::Semver.parse("abc").should be_nil
    end

    it "returns nil for too many parts" do
      Shards::Audit::Semver.parse("1.2.3.4").should be_nil
    end
  end

  describe "<=>" do
    it "compares major versions" do
      v1 = Shards::Audit::Semver.parse("2.0.0").not_nil!
      v2 = Shards::Audit::Semver.parse("1.0.0").not_nil!
      (v1 > v2).should be_true
    end

    it "compares minor versions" do
      v1 = Shards::Audit::Semver.parse("1.2.0").not_nil!
      v2 = Shards::Audit::Semver.parse("1.1.0").not_nil!
      (v1 > v2).should be_true
    end

    it "compares patch versions" do
      v1 = Shards::Audit::Semver.parse("1.0.2").not_nil!
      v2 = Shards::Audit::Semver.parse("1.0.1").not_nil!
      (v1 > v2).should be_true
    end

    it "treats equal versions as equal" do
      v1 = Shards::Audit::Semver.parse("1.2.3").not_nil!
      v2 = Shards::Audit::Semver.parse("1.2.3").not_nil!
      (v1 == v2).should be_true
    end

    it "release > prerelease for same version" do
      release = Shards::Audit::Semver.parse("1.0.0").not_nil!
      pre = Shards::Audit::Semver.parse("1.0.0-rc1").not_nil!
      (release > pre).should be_true
    end

    it "compares prerelease strings lexically" do
      alpha = Shards::Audit::Semver.parse("1.0.0-alpha").not_nil!
      beta = Shards::Audit::Semver.parse("1.0.0-beta").not_nil!
      (beta > alpha).should be_true
    end
  end
end

describe Shards::Audit::SemverRange do
  describe "#includes?" do
    it "includes version in range" do
      range = Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.new(1, 0, 0),
        fixed: Shards::Audit::Semver.new(2, 0, 0)
      )
      v = Shards::Audit::Semver.parse("1.5.0").not_nil!
      range.includes?(v).should be_true
    end

    it "excludes version below range" do
      range = Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.new(1, 0, 0),
        fixed: Shards::Audit::Semver.new(2, 0, 0)
      )
      v = Shards::Audit::Semver.parse("0.9.0").not_nil!
      range.includes?(v).should be_false
    end

    it "excludes version at or above fixed" do
      range = Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.new(1, 0, 0),
        fixed: Shards::Audit::Semver.new(2, 0, 0)
      )
      v = Shards::Audit::Semver.parse("2.0.0").not_nil!
      range.includes?(v).should be_false
    end

    it "includes introduced boundary" do
      range = Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.new(1, 0, 0),
        fixed: Shards::Audit::Semver.new(2, 0, 0)
      )
      v = Shards::Audit::Semver.parse("1.0.0").not_nil!
      range.includes?(v).should be_true
    end

    it "handles nil introduced (from 0.0.0)" do
      range = Shards::Audit::SemverRange.new(
        introduced: nil,
        fixed: Shards::Audit::Semver.new(1, 5, 0)
      )
      v = Shards::Audit::Semver.parse("1.0.0").not_nil!
      range.includes?(v).should be_true
    end

    it "handles nil fixed (no patch yet)" do
      range = Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.new(1, 0, 0),
        fixed: nil
      )
      v = Shards::Audit::Semver.parse("99.0.0").not_nil!
      range.includes?(v).should be_true
    end

    it "excludes introduced boundary when introduced_exclusive" do
      range = Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.new(1, 0, 0),
        fixed: Shards::Audit::Semver.new(2, 0, 0),
        introduced_exclusive: true
      )
      v_at = Shards::Audit::Semver.parse("1.0.0").not_nil!
      v_above = Shards::Audit::Semver.parse("1.0.1").not_nil!
      range.includes?(v_at).should be_false
      range.includes?(v_above).should be_true
    end

    it "includes fixed boundary when fixed_inclusive" do
      range = Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.new(1, 0, 0),
        fixed: Shards::Audit::Semver.new(2, 0, 0),
        fixed_inclusive: true
      )
      v_at = Shards::Audit::Semver.parse("2.0.0").not_nil!
      v_above = Shards::Audit::Semver.parse("2.0.1").not_nil!
      range.includes?(v_at).should be_true
      range.includes?(v_above).should be_false
    end

    it "matches exact version with both exclusive and inclusive flags" do
      # Simulates "= 1.5.0" → introduced=1.5.0, fixed=1.5.0, fixed_inclusive=true
      range = Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.new(1, 5, 0),
        fixed: Shards::Audit::Semver.new(1, 5, 0),
        fixed_inclusive: true
      )
      v_match = Shards::Audit::Semver.parse("1.5.0").not_nil!
      v_below = Shards::Audit::Semver.parse("1.4.9").not_nil!
      v_above = Shards::Audit::Semver.parse("1.5.1").not_nil!
      range.includes?(v_match).should be_true
      range.includes?(v_below).should be_false
      range.includes?(v_above).should be_false
    end
  end
end

describe Shards::Audit::SemverRangeParser do
  describe ".parse_osv_events" do
    it "parses introduced/fixed pair" do
      events = JSON.parse(%([{"introduced":"0"}, {"fixed":"1.2.3"}])).as_a
      ranges = Shards::Audit::SemverRangeParser.parse_osv_events(events)
      ranges.size.should eq(1)
      ranges[0].introduced.should_not be_nil
      ranges[0].fixed.should_not be_nil
      ranges[0].fixed.not_nil!.major.should eq(1)
      ranges[0].fixed.not_nil!.minor.should eq(2)
      ranges[0].fixed.not_nil!.patch.should eq(3)
    end

    it "parses introduced with no fix" do
      events = JSON.parse(%([{"introduced":"1.0.0"}])).as_a
      ranges = Shards::Audit::SemverRangeParser.parse_osv_events(events)
      ranges.size.should eq(1)
      ranges[0].introduced.should_not be_nil
      ranges[0].fixed.should be_nil
    end

    it "parses multiple ranges" do
      events = JSON.parse(%([
        {"introduced":"0"},
        {"fixed":"1.0.0"},
        {"introduced":"2.0.0"},
        {"fixed":"2.1.0"}
      ])).as_a
      ranges = Shards::Audit::SemverRangeParser.parse_osv_events(events)
      ranges.size.should eq(2)
    end
  end

  describe ".parse_github_range" do
    it "parses >= and < range" do
      ranges = Shards::Audit::SemverRangeParser.parse_github_range(">= 1.0.0, < 2.0.0")
      ranges.size.should eq(1)
      ranges[0].introduced.not_nil!.major.should eq(1)
      ranges[0].fixed.not_nil!.major.should eq(2)
    end

    it "parses >= only (no upper bound)" do
      ranges = Shards::Audit::SemverRangeParser.parse_github_range(">= 1.0.0")
      ranges.size.should eq(1)
      ranges[0].introduced.not_nil!.major.should eq(1)
      ranges[0].fixed.should be_nil
    end

    it "returns empty for empty string" do
      ranges = Shards::Audit::SemverRangeParser.parse_github_range("")
      ranges.should be_empty
    end

    it "parses = exact version" do
      ranges = Shards::Audit::SemverRangeParser.parse_github_range("= 1.5.0")
      ranges.size.should eq(1)
      v = Shards::Audit::Semver.parse("1.5.0").not_nil!
      ranges[0].includes?(v).should be_true
      v2 = Shards::Audit::Semver.parse("1.5.1").not_nil!
      ranges[0].includes?(v2).should be_false
    end

    it "parses > with exclusive lower bound" do
      ranges = Shards::Audit::SemverRangeParser.parse_github_range("> 1.0.0, < 2.0.0")
      ranges.size.should eq(1)
      v_at = Shards::Audit::Semver.parse("1.0.0").not_nil!
      v_above = Shards::Audit::Semver.parse("1.0.1").not_nil!
      ranges[0].includes?(v_at).should be_false
      ranges[0].includes?(v_above).should be_true
    end

    it "parses <= with inclusive upper bound" do
      ranges = Shards::Audit::SemverRangeParser.parse_github_range(">= 1.0.0, <= 2.0.0")
      ranges.size.should eq(1)
      v_at = Shards::Audit::Semver.parse("2.0.0").not_nil!
      v_above = Shards::Audit::Semver.parse("2.0.1").not_nil!
      ranges[0].includes?(v_at).should be_true
      ranges[0].includes?(v_above).should be_false
    end

    it "handles > edge case without overflow" do
      ranges = Shards::Audit::SemverRangeParser.parse_github_range("> 1.2.255")
      ranges.size.should eq(1)
      v_at = Shards::Audit::Semver.parse("1.2.255").not_nil!
      v_above = Shards::Audit::Semver.parse("1.3.0").not_nil!
      ranges[0].includes?(v_at).should be_false
      ranges[0].includes?(v_above).should be_true
    end
  end
end

describe "Semver prerelease ordering (SemVer 2.0.0)" do
  it "compares numeric prerelease identifiers numerically, not lexically" do
    v2 = Shards::Audit::Semver.parse("1.0.0-rc.2").not_nil!
    v10 = Shards::Audit::Semver.parse("1.0.0-rc.10").not_nil!
    (v2 < v10).should be_true
    (v10 > v2).should be_true
  end

  it "ranks numeric identifiers below non-numeric at the same position" do
    v_num = Shards::Audit::Semver.parse("1.0.0-1").not_nil!
    v_alpha = Shards::Audit::Semver.parse("1.0.0-alpha").not_nil!
    (v_num < v_alpha).should be_true
  end

  it "ranks shorter identifier sets lower when leading identifiers match" do
    v_short = Shards::Audit::Semver.parse("1.0.0-alpha").not_nil!
    v_long = Shards::Audit::Semver.parse("1.0.0-alpha.1").not_nil!
    (v_short < v_long).should be_true
  end

  it "classifies a vulnerable rc2 install against a fix at rc.10" do
    # Range: introduced=1.0.0-rc.1, fixed=1.0.0-rc.10
    # Install: 1.0.0-rc.2 — must be classified as still in range.
    range = Shards::Audit::SemverRange.new(
      introduced: Shards::Audit::Semver.parse("1.0.0-rc.1").not_nil!,
      fixed: Shards::Audit::Semver.parse("1.0.0-rc.10").not_nil!
    )
    installed = Shards::Audit::Semver.parse("1.0.0-rc.2").not_nil!
    range.includes?(installed).should be_true
  end

  it "treats two equal prerelease strings as equal" do
    a = Shards::Audit::Semver.parse("1.0.0-beta.1").not_nil!
    b = Shards::Audit::Semver.parse("1.0.0-beta.1").not_nil!
    (a <=> b).should eq(0)
  end
end
