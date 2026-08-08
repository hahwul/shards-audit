require "../../../spec_helper"

private class CvssProbe
  include Shards::Audit::CvssParser

  def score(vector : String)
    parse_cvss_score(vector).try(&.[0])
  end

  def rank(vector : String)
    parse_cvss_score(vector).try(&.[1])
  end
end

describe Shards::Audit::CvssParser do
  probe = CvssProbe.new

  describe "official CVSS v3.1 base scores" do
    # Reference vectors and scores from the FIRST CVSS v3.1 specification
    # and calculator. The previous additive heuristic matched none of them.
    {
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" => 9.8,
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" => 7.5,
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" => 10.0,
      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" => 7.8,
      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" => 3.1,
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" => 6.1,
      "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L" => 1.6,
      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" => 6.5,
    }.each do |vector, expected|
      it "scores #{vector} as #{expected}" do
        probe.score(vector).should eq(expected)
      end
    end

    it "returns 0.0 when every impact metric is None" do
      probe.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").should eq(0.0)
    end
  end

  describe "CVSS v3.0" do
    it "scores v3.0 vectors" do
      probe.score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").should eq(7.5)
    end

    it "ranks v3.1 above v3.0 so the newest vector wins" do
      v31 = probe.rank("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").not_nil!
      v30 = probe.rank("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").not_nil!
      v31.should be > v30
    end
  end

  describe "vectors we do not score" do
    # The old heuristic scored a 9.8-critical v4 vector at ~5.0 ("MEDIUM"),
    # which `--severity-threshold high` then hid entirely. Declining to
    # score leaves severity Unknown, which always surfaces.
    it "declines CVSS v4.0 rather than guessing" do
      probe.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").should be_nil
    end

    it "declines CVSS v2 vectors, which carry no CVSS: prefix" do
      probe.score("AV:N/AC:L/Au:N/C:P/I:P/A:P").should be_nil
    end

    it "declines a vector missing required metrics" do
      probe.score("CVSS:3.1/AV:N/AC:L").should be_nil
    end

    it "declines a vector with an unknown metric value" do
      probe.score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").should be_nil
    end

    it "declines empty and garbage input" do
      probe.score("").should be_nil
      probe.score("not a vector").should be_nil
      probe.score("CVSS:").should be_nil
    end
  end

  describe "severity mapping" do
    it "maps computed scores onto the documented bands" do
      Shards::Audit::Severity.from_cvss(probe.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").not_nil!)
        .should eq(Shards::Audit::Severity::Critical)
      Shards::Audit::Severity.from_cvss(probe.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").not_nil!)
        .should eq(Shards::Audit::Severity::Medium)
    end
  end
end
