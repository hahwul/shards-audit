require "../../spec_helper"
require "file_utils"

describe Shards::Audit::Cache do
  around_each do |example|
    tmp_dir = File.tempname("shards-audit-cache-test")
    Dir.mkdir_p(tmp_dir)
    begin
      example.run
    ensure
      FileUtils.rm_rf(tmp_dir) if Dir.exists?(tmp_dir)
    end
  end

  describe "#get and #set" do
    it "returns nil for missing key" do
      tmp_dir = File.tempname("shards-audit-cache-test")
      cache = Shards::Audit::Cache.new(tmp_dir)
      cache.get("osv/vulns/GHSA-1234.json").should be_nil
      FileUtils.rm_rf(tmp_dir) if Dir.exists?(tmp_dir)
    end

    it "stores and retrieves a value" do
      tmp_dir = File.tempname("shards-audit-cache-test")
      Dir.mkdir_p(tmp_dir)
      cache = Shards::Audit::Cache.new(tmp_dir)
      cache.set("osv/vulns/GHSA-1234.json", %({"id":"GHSA-1234"}))
      cache.get("osv/vulns/GHSA-1234.json").should eq(%({"id":"GHSA-1234"}))
      FileUtils.rm_rf(tmp_dir)
    end

    it "stores nested keys with auto-created directories" do
      tmp_dir = File.tempname("shards-audit-cache-test")
      cache = Shards::Audit::Cache.new(tmp_dir)
      cache.set("github/owner/repo.json", "[]")
      cache.get("github/owner/repo.json").should eq("[]")
      Dir.exists?(File.join(tmp_dir, "github", "owner")).should be_true
      FileUtils.rm_rf(tmp_dir)
    end
  end

  describe "TTL expiration" do
    it "returns nil for expired entries" do
      tmp_dir = File.tempname("shards-audit-cache-test")
      Dir.mkdir_p(tmp_dir)
      cache = Shards::Audit::Cache.new(tmp_dir, ttl_seconds: 1)
      cache.set("key.json", "value")
      sleep 1.1.seconds
      cache.get("key.json").should be_nil
      FileUtils.rm_rf(tmp_dir)
    end

    it "returns value within TTL" do
      tmp_dir = File.tempname("shards-audit-cache-test")
      Dir.mkdir_p(tmp_dir)
      cache = Shards::Audit::Cache.new(tmp_dir, ttl_seconds: 60)
      cache.set("key.json", "value")
      cache.get("key.json").should eq("value")
      FileUtils.rm_rf(tmp_dir)
    end
  end

  describe "#clear" do
    it "removes all cached files" do
      tmp_dir = File.tempname("shards-audit-cache-test")
      Dir.mkdir_p(tmp_dir)
      cache = Shards::Audit::Cache.new(tmp_dir)
      cache.set("osv/vulns/A.json", "a")
      cache.set("github/owner/repo.json", "b")
      cache.clear
      Dir.exists?(tmp_dir).should be_false
      FileUtils.rm_rf(tmp_dir) if Dir.exists?(tmp_dir)
    end

    it "does nothing when directory does not exist" do
      tmp_dir = File.tempname("shards-audit-cache-test")
      cache = Shards::Audit::Cache.new(tmp_dir)
      cache.clear # should not raise
    end
  end

  describe "value size limit" do
    it "silently rejects values exceeding MAX_CACHE_VALUE_SIZE" do
      tmp_dir = File.tempname("shards-audit-cache-test")
      Dir.mkdir_p(tmp_dir)
      cache = Shards::Audit::Cache.new(tmp_dir)
      oversized = "x" * (Shards::Audit::Cache::MAX_CACHE_VALUE_SIZE + 1)
      cache.set("big.json", oversized)
      cache.get("big.json").should be_nil
      FileUtils.rm_rf(tmp_dir)
    end

    it "accepts values at exactly MAX_CACHE_VALUE_SIZE" do
      tmp_dir = File.tempname("shards-audit-cache-test")
      Dir.mkdir_p(tmp_dir)
      cache = Shards::Audit::Cache.new(tmp_dir)
      exact = "x" * Shards::Audit::Cache::MAX_CACHE_VALUE_SIZE
      cache.set("exact.json", exact)
      cache.get("exact.json").should eq(exact)
      FileUtils.rm_rf(tmp_dir)
    end
  end

  describe "directory auto-creation" do
    it "creates base directory on first set" do
      tmp_dir = File.tempname("shards-audit-cache-test")
      Dir.exists?(tmp_dir).should be_false
      cache = Shards::Audit::Cache.new(tmp_dir)
      cache.set("test.json", "data")
      Dir.exists?(tmp_dir).should be_true
      FileUtils.rm_rf(tmp_dir)
    end
  end
end
