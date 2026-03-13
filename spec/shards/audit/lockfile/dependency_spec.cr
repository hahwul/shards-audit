require "../../../spec_helper"

describe Shards::Audit::Dependency do
  describe "#github_owner_repo" do
    it "extracts owner/repo from HTTPS GitHub URL" do
      dep = Shards::Audit::Dependency.new(
        name: "kemal",
        git_url: "https://github.com/kemalcr/kemal.git",
        version: "1.1.2"
      )
      dep.github_owner_repo.should eq("kemalcr/kemal")
    end

    it "extracts owner/repo from SSH GitHub URL" do
      dep = Shards::Audit::Dependency.new(
        name: "kemal",
        git_url: "git@github.com:kemalcr/kemal.git",
        version: "1.1.2"
      )
      dep.github_owner_repo.should eq("kemalcr/kemal")
    end

    it "returns nil for non-GitHub URLs" do
      dep = Shards::Audit::Dependency.new(
        name: "my-shard",
        git_url: "https://gitlab.com/user/my-shard.git",
        version: "0.1.0"
      )
      dep.github_owner_repo.should be_nil
    end
  end

  describe "#github?" do
    it "returns true for GitHub URLs" do
      dep = Shards::Audit::Dependency.new(
        name: "kemal",
        git_url: "https://github.com/kemalcr/kemal.git"
      )
      dep.github?.should be_true
    end

    it "returns false for non-GitHub URLs" do
      dep = Shards::Audit::Dependency.new(
        name: "my-shard",
        git_url: "https://gitlab.com/user/my-shard.git"
      )
      dep.github?.should be_false
    end
  end

  describe "#to_s" do
    it "includes name and version" do
      dep = Shards::Audit::Dependency.new(
        name: "kemal",
        git_url: "https://github.com/kemalcr/kemal.git",
        version: "1.1.2"
      )
      dep.to_s.should eq("kemal (1.1.2)")
    end

    it "includes commit hash (truncated)" do
      dep = Shards::Audit::Dependency.new(
        name: "lucky",
        git_url: "https://github.com/luckyframework/lucky.git",
        commit: "deadbeef12345678"
      )
      dep.to_s.should eq("lucky [deadbee]")
    end

    it "includes both version and commit" do
      dep = Shards::Audit::Dependency.new(
        name: "ameba",
        git_url: "https://github.com/crystal-ameba/ameba.git",
        version: "1.5.0",
        commit: "abc1234def5678"
      )
      dep.to_s.should eq("ameba (1.5.0) [abc1234]")
    end

    it "shows only name when no version or commit" do
      dep = Shards::Audit::Dependency.new(
        name: "bare-shard",
        git_url: "https://github.com/user/bare-shard.git"
      )
      dep.to_s.should eq("bare-shard")
    end
  end

  describe "#github_owner_repo" do
    it "handles owner/repo with hyphens and underscores" do
      dep = Shards::Audit::Dependency.new(
        name: "my-shard",
        git_url: "https://github.com/my-org_name/my-repo_name.git"
      )
      dep.github_owner_repo.should eq("my-org_name/my-repo_name")
    end

    it "handles GitHub URL without .git extension" do
      dep = Shards::Audit::Dependency.new(
        name: "kemal",
        git_url: "https://github.com/kemalcr/kemal"
      )
      dep.github_owner_repo.should eq("kemalcr/kemal")
    end
  end
end
