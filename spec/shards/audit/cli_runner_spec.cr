require "../../spec_helper"

private def run_cli_capture(args : Array(String)) : {Int32, String, String}
  stdout = IO::Memory.new
  stderr = IO::Memory.new
  Shards::Audit::CLI.stdout = stdout
  Shards::Audit::CLI.stderr = stderr
  exit_code = Shards::Audit::CLI.run(args)
  {exit_code, stdout.to_s, stderr.to_s}
ensure
  Shards::Audit::CLI.stdout = STDOUT
  Shards::Audit::CLI.stderr = STDERR
end

describe "CLI Runner integration" do
  describe "lockfile parsing" do
    it "returns EXIT_CLEAN for empty lockfile" do
      exit_code, stdout, _ = run_cli_capture(["--path", File.join(FIXTURES_PATH, "shard.lock.empty")])
      exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
      stdout.should contain("No dependencies found")
    end

    it "returns EXIT_ERROR for missing lockfile" do
      exit_code, _, stderr = run_cli_capture(["--path", "/tmp/nonexistent_shard.lock"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
      stderr.should contain("Lockfile not found")
    end
  end

  describe "--exit-zero" do
    it "returns EXIT_CLEAN even with non-empty lockfile" do
      exit_code, _, _ = run_cli_capture([
        "--path", File.join(FIXTURES_PATH, "shard.lock.basic"),
        "--exit-zero",
        "--no-cache",
      ])
      exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
    end
  end

  describe "output formats" do
    it "outputs valid JSON with --format json" do
      _, stdout, _ = run_cli_capture([
        "--path", File.join(FIXTURES_PATH, "shard.lock.basic"),
        "--format", "json",
        "--no-cache",
      ])
      parsed = JSON.parse(stdout)
      parsed["tool_version"].as_s.should eq(Shards::Audit::VERSION)
      parsed["dependencies_scanned"].as_i.should eq(3)
      parsed["vulnerabilities"].as_a.should be_a(Array(JSON::Any))
    end

    it "outputs valid YAML with --format yaml" do
      _, stdout, _ = run_cli_capture([
        "--path", File.join(FIXTURES_PATH, "shard.lock.basic"),
        "--format", "yaml",
        "--no-cache",
      ])
      parsed = YAML.parse(stdout)
      parsed["tool_version"].as_s.should eq(Shards::Audit::VERSION)
      parsed["dependencies_scanned"].as_i.should eq(3)
    end

    it "accepts yml as alias for yaml" do
      exit_code, _, _ = run_cli_capture([
        "--path", File.join(FIXTURES_PATH, "shard.lock.basic"),
        "--format", "yml",
        "--no-cache",
      ])
      exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
    end

    it "outputs TOML with --format toml" do
      _, stdout, _ = run_cli_capture([
        "--path", File.join(FIXTURES_PATH, "shard.lock.basic"),
        "--format", "toml",
        "--no-cache",
      ])
      stdout.should contain("tool_version = \"#{Shards::Audit::VERSION}\"")
      stdout.should contain("dependencies_scanned = 3")
    end
  end

  describe "--no-config" do
    it "does not load config file when --no-config is set" do
      exit_code, _, _ = run_cli_capture([
        "--path", File.join(FIXTURES_PATH, "shard.lock.empty"),
        "--no-config",
      ])
      exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
    end
  end

  describe "verbose output" do
    it "prints scan details to stderr with --verbose" do
      _, _, stderr = run_cli_capture([
        "--path", File.join(FIXTURES_PATH, "shard.lock.basic"),
        "--verbose",
        "--no-cache",
      ])
      stderr.should contain("Scanning 3 dependencies")
    end
  end
end
