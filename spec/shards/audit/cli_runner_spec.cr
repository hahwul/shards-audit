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
  Shards::Audit::CLI.stderr = SPEC_STDERR
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

    # A partial outage under --exit-zero exited 0 with a report, but a total
    # one exited 2 with an empty stdout, so `-f json --exit-zero` broke the
    # next pipeline step exactly when the network was down.
    it "still exits 0 with a parseable report when every source failed" do
      previous = ENV["HTTPS_PROXY"]?
      ENV["HTTPS_PROXY"] = "http://127.0.0.1:1" # refuses every connection
      begin
        exit_code, stdout, stderr = run_cli_capture([
          "--path", File.join(FIXTURES_PATH, "shard.lock.basic"), "--no-cache", "--no-config",
          "--timeout", "1", "-f", "json", "--exit-zero",
        ])
        exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
        JSON.parse(stdout)["errors"].as_a.size.should eq(2)
        stderr.should contain("All vulnerability sources failed")
      ensure
        previous ? (ENV["HTTPS_PROXY"] = previous) : ENV.delete("HTTPS_PROXY")
      end
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

    # Deliberately runs against the empty lockfile: the assertion is about
    # the alias selecting the YAML formatter, and pointing it at a lockfile
    # with real dependencies made the exit code depend on whether the
    # advisory APIs answered.
    it "accepts yml as alias for yaml" do
      exit_code, stdout, _ = run_cli_capture([
        "--path", File.join(FIXTURES_PATH, "shard.lock.empty"),
        "--format", "yml",
        "--no-cache",
      ])
      exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
      YAML.parse(stdout)["dependencies_scanned"].as_i.should eq(0)
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

  describe "--config" do
    it "exits 2 when an explicit config file is missing" do
      exit_code, _, stderr = run_cli_capture([
        "--path", File.join(FIXTURES_PATH, "shard.lock.empty"),
        "--config", "/nonexistent/.shards-audit.yml",
      ])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
      stderr.should contain("Error: Config file not found: /nonexistent/.shards-audit.yml")
    end

    it "exits 2 when an explicit config file is malformed" do
      {"ignore: [unclosed\n", "- just\n- a list\n"}.each do |content|
        path = File.tempname("shards-audit", ".yml")
        File.write(path, content)
        begin
          exit_code, _, stderr = run_cli_capture([
            "--path", File.join(FIXTURES_PATH, "shard.lock.empty"),
            "--config", path,
          ])
          exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
          stderr.should contain("Error: Failed to load config file #{path}")
        ensure
          File.delete(path)
        end
      end
    end

    it "only warns about a malformed implicit config file" do
      dir = File.tempname("shards-audit")
      Dir.mkdir(dir)
      File.write(File.join(dir, ".shards-audit.yml"), "- not a mapping\n")
      File.copy(File.join(FIXTURES_PATH, "shard.lock.empty"), File.join(dir, "shard.lock"))
      begin
        exit_code, _, stderr = Dir.cd(dir) { run_cli_capture(["--path", "shard.lock"]) }
        exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
        stderr.should contain("Warning: Failed to load config file")
      ensure
        FileUtils.rm_rf(dir)
      end
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
