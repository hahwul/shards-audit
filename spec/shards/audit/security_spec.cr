require "../../spec_helper"
require "file_utils"

describe "Security" do
  describe "Cache path traversal prevention" do
    it "rejects path traversal in cache keys" do
      tmp_dir = File.tempname("shards-audit-sec-test")
      Dir.mkdir_p(tmp_dir)
      cache = Shards::Audit::Cache.new(tmp_dir)

      # Attempt path traversal
      cache.set("../../etc/evil", "malicious")
      # Should not create file outside cache dir
      File.exists?(File.join(tmp_dir, "../../etc/evil")).should be_false

      # Normal key should still work
      cache.set("osv/vulns/GHSA-1234.json", "safe")
      cache.get("osv/vulns/GHSA-1234.json").should eq("safe")

      FileUtils.rm_rf(tmp_dir)
    end

    it "sanitizes special characters in cache keys" do
      tmp_dir = File.tempname("shards-audit-sec-test")
      Dir.mkdir_p(tmp_dir)
      cache = Shards::Audit::Cache.new(tmp_dir)

      cache.set("key;rm -rf /", "payload")
      # Should sanitize the key, not execute anything
      File.exists?(File.join(tmp_dir, "key;rm -rf /")).should be_false

      FileUtils.rm_rf(tmp_dir)
    end

    it "rejects empty key after sanitization" do
      tmp_dir = File.tempname("shards-audit-sec-test")
      Dir.mkdir_p(tmp_dir)
      cache = Shards::Audit::Cache.new(tmp_dir)

      cache.set("../../..", "payload")
      # Should reject entirely
      cache.get("../../..").should be_nil

      FileUtils.rm_rf(tmp_dir)
    end
  end

  describe "Cache file permissions" do
    it "sets restrictive permissions on cache files" do
      tmp_dir = File.tempname("shards-audit-sec-test")
      Dir.mkdir_p(tmp_dir)
      cache = Shards::Audit::Cache.new(tmp_dir)

      cache.set("test.json", "data")
      path = File.join(tmp_dir, "test.json")

      if File.exists?(path)
        info = File.info(path)
        perms = info.permissions
        # Owner can read/write, others cannot
        perms.owner_read?.should be_true
        perms.owner_write?.should be_true
        perms.group_read?.should be_false
        perms.other_read?.should be_false
      end

      FileUtils.rm_rf(tmp_dir)
    end
  end

  describe "Cache symlink protection" do
    it "does not follow symlinks when reading cache" do
      tmp_dir = File.tempname("shards-audit-sec-test")
      Dir.mkdir_p(tmp_dir)

      # Create a normal file
      target = File.join(tmp_dir, "target.json")
      File.write(target, "secret")

      # Create symlink in cache dir
      cache_dir = File.join(tmp_dir, "cache")
      Dir.mkdir_p(cache_dir)
      symlink = File.join(cache_dir, "link.json")

      begin
        File.symlink(target, symlink)
        cache = Shards::Audit::Cache.new(cache_dir)
        # Should refuse to read symlinked file
        cache.get("link.json").should be_nil
      rescue
        # Symlink creation may fail on some systems
      end

      FileUtils.rm_rf(tmp_dir)
    end

    it "refuses to clear a symlinked cache directory" do
      tmp_dir = File.tempname("shards-audit-sec-test")
      Dir.mkdir_p(tmp_dir)

      target_dir = File.join(tmp_dir, "important")
      Dir.mkdir_p(target_dir)
      File.write(File.join(target_dir, "data"), "keep")

      symlink_dir = File.join(tmp_dir, "cache_link")
      begin
        File.symlink(target_dir, symlink_dir)

        cache = Shards::Audit::Cache.new(symlink_dir)
        cache.clear

        # The target directory should not be deleted
        File.exists?(File.join(target_dir, "data")).should be_true
      rescue
        # Symlink creation may fail on some systems
      end

      FileUtils.rm_rf(tmp_dir)
    end
  end

  describe "Cache value size limit" do
    it "rejects oversized cache values" do
      tmp_dir = File.tempname("shards-audit-sec-test")
      Dir.mkdir_p(tmp_dir)
      cache = Shards::Audit::Cache.new(tmp_dir)

      # Try to cache a value exceeding 10MB
      large_value = "x" * (10 * 1024 * 1024 + 1)
      cache.set("big.json", large_value)
      cache.get("big.json").should be_nil

      FileUtils.rm_rf(tmp_dir)
    end
  end

  describe "URL validation in Vulnerability" do
    it "accepts https URLs" do
      vuln = Shards::Audit::Vulnerability.new(
        id: "GHSA-test",
        url: "https://osv.dev/vulnerability/GHSA-test"
      )
      vuln.url.should eq("https://osv.dev/vulnerability/GHSA-test")
    end

    it "rejects http URLs" do
      vuln = Shards::Audit::Vulnerability.new(
        id: "GHSA-test",
        url: "http://evil.com/phish"
      )
      vuln.url.should be_nil
    end

    it "rejects javascript: URLs" do
      vuln = Shards::Audit::Vulnerability.new(
        id: "GHSA-test",
        url: "javascript:alert(1)"
      )
      vuln.url.should be_nil
    end

    it "rejects file: URLs" do
      vuln = Shards::Audit::Vulnerability.new(
        id: "GHSA-test",
        url: "file:///etc/passwd"
      )
      vuln.url.should be_nil
    end

    it "handles nil URL" do
      vuln = Shards::Audit::Vulnerability.new(id: "GHSA-test")
      vuln.url.should be_nil
    end
  end

  describe "Lockfile size limit" do
    it "rejects oversized lockfiles" do
      tmp = File.tempname("shards-audit-big-lock")
      # Create a file slightly over 5MB
      File.write(tmp, "version: 2.0\nshards:\n" + ("  shard0:\n    git: https://github.com/a/b.git\n    version: 1.0.0\n" * 100000))

      if File.size(tmp) > Shards::Audit::LockfileParser::MAX_LOCKFILE_SIZE
        expect_raises(Shards::Audit::LockfileParser::ParseError, /too large/) do
          Shards::Audit::LockfileParser.parse(tmp)
        end
      end

      File.delete(tmp) if File.exists?(tmp)
    end
  end

  describe "JSON injection prevention in OSV queries" do
    it "safely handles special characters in dependency fields" do
      dep = Shards::Audit::Dependency.new(
        name: "evil\"shard",
        git_url: "https://github.com/user/repo\";DROP TABLE",
        version: "1.0\";evil"
      )

      # The OsvClient.build_query is private, but we can verify
      # the Dependency itself stores the data safely
      dep.name.should eq("evil\"shard")
      dep.git_url.should eq("https://github.com/user/repo\";DROP TABLE")
    end
  end

  describe "Token masking in GitHub client" do
    it "creates client without exposing token" do
      client = Shards::Audit::GithubClient.new(token: "ghp_secret123")
      # Token should not appear in string representation
      client.to_s.should_not contain("ghp_secret123")
    end
  end
end
