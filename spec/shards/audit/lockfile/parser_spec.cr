require "../../../spec_helper"

describe Shards::Audit::LockfileParser do
  describe ".parse" do
    it "parses basic shard.lock with versions" do
      deps = Shards::Audit::LockfileParser.parse(File.join(FIXTURES_PATH, "shard.lock.basic")).dependencies
      deps.size.should eq(3)

      kemal = deps.find { |d| d.name == "kemal" }.not_nil!
      kemal.version.should eq("1.1.2")
      kemal.git_url.should eq("https://github.com/kemalcr/kemal.git")
      kemal.commit.should be_nil
    end

    it "parses shard.lock with commit hashes" do
      deps = Shards::Audit::LockfileParser.parse(File.join(FIXTURES_PATH, "shard.lock.commit")).dependencies
      deps.size.should eq(2)

      ameba = deps.find { |d| d.name == "ameba" }.not_nil!
      ameba.version.should eq("1.5.0")
      ameba.commit.should eq("abc1234def5678")

      lucky = deps.find { |d| d.name == "lucky" }.not_nil!
      lucky.version.should be_nil
      lucky.commit.should eq("deadbeef12345678")
    end

    it "parses mixed dependencies" do
      deps = Shards::Audit::LockfileParser.parse(File.join(FIXTURES_PATH, "shard.lock.mixed")).dependencies
      deps.size.should eq(3)

      github_deps = deps.select(&.github?)
      github_deps.size.should eq(2)
    end

    it "returns empty array for empty shards" do
      result = Shards::Audit::LockfileParser.parse(File.join(FIXTURES_PATH, "shard.lock.empty"))
      result.dependencies.should be_empty
    end

    it "raises ParseError for oversized lockfile" do
      tmp_file = File.tempname("shard-lock-big")
      File.write(tmp_file, "x" * (Shards::Audit::LockfileParser::MAX_LOCKFILE_SIZE + 1))
      begin
        expect_raises(Shards::Audit::LockfileParser::ParseError, /too large/) do
          Shards::Audit::LockfileParser.parse(tmp_file)
        end
      ensure
        File.delete(tmp_file) if File.exists?(tmp_file)
      end
    end

    it "raises ParseError for missing file" do
      expect_raises(Shards::Audit::LockfileParser::ParseError, /not found/) do
        Shards::Audit::LockfileParser.parse("/nonexistent/shard.lock")
      end
    end
  end

  describe ".parse_content" do
    it "raises ParseError for invalid YAML" do
      expect_raises(Shards::Audit::LockfileParser::ParseError, /missing 'shards' key/) do
        Shards::Audit::LockfileParser.parse_content("version: 2.0\n")
      end
    end

    it "parses version with embedded commit hash" do
      content = <<-YAML
      version: 2.0
      shards:
        some-shard:
          git: https://github.com/user/some-shard.git
          version: 1.0.0+git.commit.abc123def
      YAML

      result = Shards::Audit::LockfileParser.parse_content(content)
      result.dependencies.size.should eq(1)
      result.dependencies[0].name.should eq("some-shard")
      result.dependencies[0].version.should eq("1.0.0")
      result.dependencies[0].commit.should eq("abc123def")
    end

    it "skips entries without git URL and tracks them" do
      content = <<-YAML
      version: 2.0
      shards:
        local-shard:
          path: ../local-shard
          version: 0.1.0
        git-shard:
          git: https://github.com/user/git-shard.git
          version: 1.0.0
      YAML

      result = Shards::Audit::LockfileParser.parse_content(content)
      result.dependencies.size.should eq(1)
      result.dependencies[0].name.should eq("git-shard")
      result.skipped_deps.should eq(["local-shard"])
    end

    it "handles shard with only commit, no version" do
      content = <<-YAML
      version: 2.0
      shards:
        edge-shard:
          git: https://github.com/user/edge-shard.git
          commit: deadbeef12345678
      YAML

      result = Shards::Audit::LockfileParser.parse_content(content)
      result.dependencies.size.should eq(1)
      result.dependencies[0].name.should eq("edge-shard")
      result.dependencies[0].version.should be_nil
      result.dependencies[0].commit.should eq("deadbeef12345678")
    end

    it "skips entries with empty name" do
      content = <<-YAML
      version: 2.0
      shards:
        "":
          git: https://github.com/user/empty-name.git
          version: 1.0.0
        valid-shard:
          git: https://github.com/user/valid.git
          version: 2.0.0
      YAML

      result = Shards::Audit::LockfileParser.parse_content(content)
      result.dependencies.size.should eq(1)
      result.dependencies[0].name.should eq("valid-shard")
    end

    it "handles empty shards hash" do
      content = <<-YAML
      version: 2.0
      shards: {}
      YAML

      result = Shards::Audit::LockfileParser.parse_content(content)
      result.dependencies.should be_empty
      result.skipped_deps.should be_empty
    end
  end
end
