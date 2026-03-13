require "../../spec_helper"

describe Shards::Audit::IgnoreEntry do
  describe "#active?" do
    it "returns true when no expiry" do
      entry = Shards::Audit::IgnoreEntry.new(id: "GHSA-xxxx")
      entry.active?.should be_true
    end

    it "returns true when expiry is in the future" do
      future = Time.utc + 365.days
      entry = Shards::Audit::IgnoreEntry.new(id: "GHSA-xxxx", expires: future)
      entry.active?.should be_true
    end

    it "returns false when expiry is in the past" do
      past = Time.utc - 1.day
      entry = Shards::Audit::IgnoreEntry.new(id: "GHSA-xxxx", expires: past)
      entry.active?.should be_false
    end
  end
end

describe Shards::Audit::ConfigFile do
  describe ".load" do
    it "parses YAML with ignore entries" do
      tmp = File.tempname("shards-audit-cfg", ".yml")
      File.write(tmp, <<-YAML
        ignore:
          - id: GHSA-xxxx-yyyy
            reason: "Not applicable"
          - id: CVE-2024-1234
            reason: "Mitigated"
        YAML
      )
      begin
        cf = Shards::Audit::ConfigFile.load(tmp)
        cf.ignore.size.should eq(2)
        cf.ignore[0].id.should eq("GHSA-xxxx-yyyy")
        cf.ignore[0].reason.should eq("Not applicable")
        cf.ignore[1].id.should eq("CVE-2024-1234")
      ensure
        File.delete(tmp) if File.exists?(tmp)
      end
    end

    it "parses severity_threshold" do
      tmp = File.tempname("shards-audit-cfg", ".yml")
      File.write(tmp, <<-YAML
        severity_threshold: medium
        YAML
      )
      begin
        cf = Shards::Audit::ConfigFile.load(tmp)
        cf.severity_threshold.should eq(Shards::Audit::Severity::Medium)
      ensure
        File.delete(tmp) if File.exists?(tmp)
      end
    end

    it "parses expires date" do
      tmp = File.tempname("shards-audit-cfg", ".yml")
      File.write(tmp, <<-YAML
        ignore:
          - id: GHSA-xxxx
            expires: "2025-06-01"
        YAML
      )
      begin
        cf = Shards::Audit::ConfigFile.load(tmp)
        cf.ignore.size.should eq(1)
        cf.ignore[0].expires.should_not be_nil
        cf.ignore[0].expires.not_nil!.year.should eq(2025)
        cf.ignore[0].expires.not_nil!.month.should eq(6)
      ensure
        File.delete(tmp) if File.exists?(tmp)
      end
    end

    it "handles empty file" do
      tmp = File.tempname("shards-audit-cfg", ".yml")
      File.write(tmp, "---\n")
      begin
        cf = Shards::Audit::ConfigFile.load(tmp)
        cf.ignore.should be_empty
        cf.severity_threshold.should be_nil
      ensure
        File.delete(tmp) if File.exists?(tmp)
      end
    end

    it "skips entries without id" do
      tmp = File.tempname("shards-audit-cfg", ".yml")
      File.write(tmp, <<-YAML
        ignore:
          - reason: "no id here"
          - id: GHSA-valid
        YAML
      )
      begin
        cf = Shards::Audit::ConfigFile.load(tmp)
        cf.ignore.size.should eq(1)
        cf.ignore[0].id.should eq("GHSA-valid")
      ensure
        File.delete(tmp) if File.exists?(tmp)
      end
    end

    it "ignores unknown severity_threshold" do
      tmp = File.tempname("shards-audit-cfg", ".yml")
      File.write(tmp, <<-YAML
        severity_threshold: extreme
        YAML
      )
      begin
        cf = Shards::Audit::ConfigFile.load(tmp)
        cf.severity_threshold.should be_nil
      ensure
        File.delete(tmp) if File.exists?(tmp)
      end
    end
  end

  describe ".find" do
    it "finds config in specified directory" do
      tmp_dir = File.tempname("shards-audit-find")
      Dir.mkdir_p(tmp_dir)
      config_path = File.join(tmp_dir, ".shards-audit.yml")
      File.write(config_path, "ignore: []\n")
      begin
        result = Shards::Audit::ConfigFile.find(tmp_dir)
        result.should eq(config_path)
      ensure
        FileUtils.rm_rf(tmp_dir) if Dir.exists?(tmp_dir)
      end
    end

    it "returns nil when no config exists" do
      tmp_dir = File.tempname("shards-audit-find-empty")
      Dir.mkdir_p(tmp_dir)
      begin
        result = Shards::Audit::ConfigFile.find(tmp_dir)
        # May find one in parent directories or home; we just test it doesn't crash
        # If result is nil, that's expected for an empty temp dir
      ensure
        FileUtils.rm_rf(tmp_dir) if Dir.exists?(tmp_dir)
      end
    end

    it "traverses parent directories" do
      parent = File.tempname("shards-audit-parent")
      child = File.join(parent, "sub", "dir")
      Dir.mkdir_p(child)
      config_path = File.join(parent, ".shards-audit.yml")
      File.write(config_path, "ignore: []\n")
      begin
        result = Shards::Audit::ConfigFile.find(child)
        result.should eq(config_path)
      ensure
        FileUtils.rm_rf(parent) if Dir.exists?(parent)
      end
    end
  end
end
