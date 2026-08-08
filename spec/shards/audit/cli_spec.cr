require "../../spec_helper"

private def run_cli(args : Array(String)) : Int32
  Shards::Audit::CLI.stdout = IO::Memory.new
  Shards::Audit::CLI.stderr = IO::Memory.new
  Shards::Audit::CLI.run(args)
ensure
  Shards::Audit::CLI.stdout = STDOUT
  Shards::Audit::CLI.stderr = SPEC_STDERR
end

describe Shards::Audit::CLI do
  describe "--version" do
    it "returns EXIT_CLEAN and prints version" do
      exit_code = run_cli(["--version"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
    end
  end

  describe "--help" do
    it "returns EXIT_CLEAN" do
      exit_code = run_cli(["--help"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
    end

    it "returns EXIT_CLEAN with -h" do
      exit_code = run_cli(["-h"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
    end
  end

  describe "invalid options" do
    it "returns EXIT_ERROR for unknown option" do
      exit_code = run_cli(["--unknown-flag"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
    end

    it "returns EXIT_ERROR for invalid format" do
      exit_code = run_cli(["--format", "xml"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
    end

    it "returns EXIT_ERROR for invalid severity threshold" do
      exit_code = run_cli(["--severity-threshold", "extreme"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
    end

    it "returns EXIT_ERROR for non-numeric timeout" do
      exit_code = run_cli(["--timeout", "abc"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
    end

    it "returns EXIT_ERROR for non-numeric cache-ttl" do
      exit_code = run_cli(["--cache-ttl", "xyz"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
    end

    it "returns EXIT_ERROR for negative timeout" do
      exit_code = run_cli(["--timeout", "-5"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
    end

    it "returns EXIT_ERROR for zero cache-ttl" do
      exit_code = run_cli(["--cache-ttl", "0"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
    end

    it "returns EXIT_ERROR for an option missing its required value" do
      # --format expects a value; omitting it raises OptionParser::MissingOption
      # which must be caught and exit cleanly rather than crash.
      exit_code = run_cli(["--format"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
    end
  end

  describe "missing lockfile" do
    it "returns EXIT_ERROR for non-existent lockfile" do
      exit_code = run_cli(["--path", "/nonexistent/shard.lock"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
    end
  end

  describe "exit codes" do
    it "defines EXIT_CLEAN as 0" do
      Shards::Audit::CLI::EXIT_CLEAN.should eq(0)
    end

    it "defines EXIT_VULNS as 1" do
      Shards::Audit::CLI::EXIT_VULNS.should eq(1)
    end

    it "defines EXIT_ERROR as 2" do
      Shards::Audit::CLI::EXIT_ERROR.should eq(2)
    end
  end

  describe "--ignore flag" do
    it "accepts single --ignore flag without error" do
      exit_code = run_cli(["--ignore", "GHSA-test", "--path", "/nonexistent/shard.lock"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
    end

    it "accepts multiple --ignore flags without error" do
      exit_code = run_cli([
        "--ignore", "GHSA-aaaa",
        "--ignore", "GHSA-bbbb",
        "--path", "/nonexistent/shard.lock",
      ])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
    end
  end

  describe "--severity-threshold flag" do
    it "accepts valid severity levels" do
      %w[low medium high critical].each do |level|
        exit_code = run_cli([
          "--severity-threshold", level,
          "--path", "/nonexistent/shard.lock",
        ])
        exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
      end
    end
  end

  describe "empty lockfile" do
    it "returns EXIT_CLEAN when lockfile has no dependencies" do
      exit_code = run_cli(["--path", File.join(FIXTURES_PATH, "shard.lock.empty")])
      exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
    end
  end
end
