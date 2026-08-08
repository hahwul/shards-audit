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

private def write_tmp(name : String, content : String) : String
  path = File.join(Dir.tempdir, "#{name}-#{Random.rand(1_000_000)}")
  File.write(path, content)
  path
end

describe Shards::Audit::Dependency do
  describe "repo names containing dots" do
    # The `.cr` suffix is the dominant Crystal shard naming convention, and
    # a `[^\/\.]+` repo pattern truncated every one of them — so advisories
    # were queried for the wrong repository and never matched.
    it "keeps a .cr suffix in the repo name" do
      dep = Shards::Audit::Dependency.new(name: "sarif", git_url: "https://github.com/hahwul/sarif.cr.git")
      dep.github_owner_repo.should eq("hahwul/sarif.cr")
    end

    it "keeps dots without a trailing .git" do
      dep = Shards::Audit::Dependency.new(name: "sarif", git_url: "https://github.com/hahwul/sarif.cr")
      dep.github_owner_repo.should eq("hahwul/sarif.cr")
    end

    it "keeps dots over SSH" do
      dep = Shards::Audit::Dependency.new(name: "sarif", git_url: "git@github.com:hahwul/sarif.cr.git")
      dep.github_owner_repo.should eq("hahwul/sarif.cr")
    end

    it "handles multiple dots" do
      dep = Shards::Audit::Dependency.new(name: "x", git_url: "https://github.com/o/a.b.c.git")
      dep.github_owner_repo.should eq("o/a.b.c")
    end
  end

  describe "URL shapes" do
    it "strips a trailing slash" do
      Shards::Audit::Dependency.new(name: "x", git_url: "https://github.com/o/r/")
        .github_owner_repo.should eq("o/r")
    end

    it "does not absorb extra path segments" do
      Shards::Audit::Dependency.new(name: "x", git_url: "https://github.com/o/r/tree/main")
        .github_owner_repo.should eq("o/r")
    end

    it "ignores a query string" do
      Shards::Audit::Dependency.new(name: "x", git_url: "https://github.com/o/r?ref=main")
        .github_owner_repo.should eq("o/r")
    end

    it "tolerates surrounding whitespace" do
      Shards::Audit::Dependency.new(name: "x", git_url: "  https://github.com/o/r.git  ")
        .github_owner_repo.should eq("o/r")
    end

    it "stays nil for non-GitHub hosts" do
      Shards::Audit::Dependency.new(name: "x", git_url: "https://gitlab.com/o/r.cr.git")
        .github_owner_repo.should be_nil
    end
  end
end

describe Shards::Audit::Semver do
  describe "build metadata" do
    # An unparseable bound in an OSV range degraded to "no bound", i.e. a
    # range matching every version.
    it "parses and ignores build metadata" do
      version = Shards::Audit::Semver.parse("1.2.3+git.abc").not_nil!
      version.to_s.should eq("1.2.3")
    end

    it "ignores build metadata after a prerelease" do
      version = Shards::Audit::Semver.parse("1.2.3-rc.1+build.5").not_nil!
      version.prerelease.should eq("rc.1")
    end

    it "treats build metadata as precedence-neutral" do
      a = Shards::Audit::Semver.parse("1.2.3+a").not_nil!
      b = Shards::Audit::Semver.parse("1.2.3+b").not_nil!
      (a <=> b).should eq(0)
    end
  end

  describe "prefix and whitespace handling" do
    it "strips a single v prefix" do
      Shards::Audit::Semver.parse("v1.2.3").not_nil!.major.should eq(1)
    end

    it "rejects a repeated v prefix instead of silently accepting it" do
      Shards::Audit::Semver.parse("vv1.2.3").should be_nil
    end

    it "tolerates surrounding whitespace" do
      Shards::Audit::Semver.parse("  1.2.3 ").not_nil!.to_s.should eq("1.2.3")
    end
  end

  describe "range constraint rendering" do
    it "renders an exclusive upper bound" do
      range = Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.parse("1.0.0"),
        fixed: Shards::Audit::Semver.parse("2.0.0"))
      range.to_constraint.should eq(">=1.0.0 <2.0.0")
    end

    it "renders an inclusive upper bound distinctly" do
      range = Shards::Audit::SemverRange.new(
        introduced: Shards::Audit::Semver.parse("1.0.0"),
        fixed: Shards::Audit::Semver.parse("2.0.0"),
        fixed_inclusive: true)
      range.to_constraint.should eq(">=1.0.0 <=2.0.0")
    end

    it "renders an unbounded range" do
      Shards::Audit::SemverRange.new.to_constraint.should eq("*")
    end
  end
end

describe Shards::Audit::LockfileParser do
  describe "malformed input" do
    # These raised past `main`, printing a backtrace and exiting 1 — the
    # code that means "vulnerabilities found".
    it "raises ParseError for invalid YAML" do
      expect_raises(Shards::Audit::LockfileParser::ParseError, /Invalid shard.lock YAML/) do
        Shards::Audit::LockfileParser.parse_content("shards: [unclosed")
      end
    end

    it "raises ParseError for a non-mapping root" do
      expect_raises(Shards::Audit::LockfileParser::ParseError, /mapping at the top level/) do
        Shards::Audit::LockfileParser.parse_content("- a\n- b\n")
      end
    end

    it "skips a shard entry that is a bare scalar" do
      result = Shards::Audit::LockfileParser.parse_content(
        "version: 2.0\nshards:\n  kemal: \"just-a-string\"\n")
      result.dependencies.should be_empty
      result.skipped_deps.should eq(["kemal"])
    end

    it "skips a shard whose git value is not a string" do
      result = Shards::Audit::LockfileParser.parse_content(
        "shards:\n  kemal:\n    git: [1, 2]\n    version: 1.0.0\n")
      result.dependencies.should be_empty
      result.skipped_deps.should eq(["kemal"])
    end

    it "skips a shard with an empty git url" do
      result = Shards::Audit::LockfileParser.parse_content(
        "shards:\n  kemal:\n    git: \"\"\n    version: 1.0.0\n")
      result.skipped_deps.should eq(["kemal"])
    end

    it "tolerates non-string version and commit values" do
      result = Shards::Audit::LockfileParser.parse_content(
        "shards:\n  kemal:\n    git: https://github.com/kemalcr/kemal.git\n    version: [1]\n    commit: {}\n")
      result.dependencies.size.should eq(1)
      result.dependencies[0].version.should be_nil
      result.dependencies[0].commit.should be_nil
    end

    it "still parses a well-formed lockfile" do
      result = Shards::Audit::LockfileParser.parse_content(
        "version: 2.0\nshards:\n  kemal:\n    git: https://github.com/kemalcr/kemal.git\n    version: 1.1.2\n")
      result.dependencies.size.should eq(1)
      result.dependencies[0].version.should eq("1.1.2")
    end
  end
end

describe Shards::Audit::CLI do
  describe "exit codes for broken input" do
    it "exits EXIT_ERROR, not EXIT_VULNS, for a malformed lockfile" do
      path = write_tmp("bad.lock", "shards: [unclosed")
      begin
        exit_code, _, stderr = run_cli_capture(["--path", path, "--no-config"])
        exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
        exit_code.should_not eq(Shards::Audit::CLI::EXIT_VULNS)
        stderr.should contain("Invalid shard.lock YAML")
      ensure
        File.delete(path) rescue nil
      end
    end

    it "exits EXIT_ERROR for a lockfile whose root is not a mapping" do
      path = write_tmp("bad2.lock", "- a\n- b\n")
      begin
        exit_code, _, _ = run_cli_capture(["--path", path, "--no-config"])
        exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
      ensure
        File.delete(path) rescue nil
      end
    end
  end
end

describe "machine formats with no dependencies" do
  # The "No dependencies found" sentence used to go to stdout whatever the
  # format, so `shards-audit -f json > out.json` wrote prose where the next
  # CI step expected JSON.
  empty_lock = File.join(FIXTURES_PATH, "shard.lock.empty")

  it "emits parseable JSON" do
    exit_code, stdout, _ = run_cli_capture(["--path", empty_lock, "--no-config", "-f", "json"])
    exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
    JSON.parse(stdout)["dependencies_scanned"].as_i.should eq(0)
  end

  it "emits parseable YAML" do
    _, stdout, _ = run_cli_capture(["--path", empty_lock, "--no-config", "-f", "yaml"])
    YAML.parse(stdout)["dependencies_scanned"].as_i.should eq(0)
  end

  it "emits SARIF carrying a results array" do
    _, stdout, _ = run_cli_capture(["--path", empty_lock, "--no-config", "-f", "sarif"])
    JSON.parse(stdout)["runs"][0]["results"].as_a.should be_empty
  end

  it "emits TOML" do
    _, stdout, _ = run_cli_capture(["--path", empty_lock, "--no-config", "-f", "toml"])
    stdout.should contain("dependencies_scanned = 0")
  end

  it "keeps the human message for the table format" do
    _, stdout, _ = run_cli_capture(["--path", empty_lock, "--no-config"])
    stdout.should contain("No dependencies found")
  end
end

describe Shards::Audit::ConfigFile do
  describe "ignore expiry" do
    it "stays active through the whole of the expiry date" do
      today = Time.utc.at_beginning_of_day
      entry = Shards::Audit::IgnoreEntry.new(id: "GHSA-1", expires: today)
      entry.active?.should be_true
    end

    it "lapses once the expiry date has passed" do
      yesterday = Time.utc.at_beginning_of_day - 1.day
      entry = Shards::Audit::IgnoreEntry.new(id: "GHSA-1", expires: yesterday)
      entry.active?.should be_false
    end

    it "never expires without a date" do
      Shards::Audit::IgnoreEntry.new(id: "GHSA-1").active?.should be_true
    end
  end

  describe "malformed config files" do
    it "returns an empty config for a top-level list" do
      path = write_tmp("cfg.yml", "- a\n- b\n")
      begin
        config = Shards::Audit::ConfigFile.load(path)
        config.ignore.should be_empty
        config.severity_threshold.should be_nil
      ensure
        File.delete(path) rescue nil
      end
    end

    it "returns an empty config for an empty file" do
      path = write_tmp("cfg.yml", "")
      begin
        Shards::Audit::ConfigFile.load(path).ignore.should be_empty
      ensure
        File.delete(path) rescue nil
      end
    end

    it "skips ignore entries that are not mappings" do
      path = write_tmp("cfg.yml", "ignore:\n  - \"GHSA-bare\"\n  - id: GHSA-ok\n")
      begin
        Shards::Audit::ConfigFile.load(path).ignore.map(&.id).should eq(["GHSA-ok"])
      ensure
        File.delete(path) rescue nil
      end
    end
  end
end

describe Shards::Audit::Config do
  describe "colour defaults" do
    # --no-color was the only off switch, so piping the table into a file or
    # a CI log captured raw escape sequences.
    it "honours NO_COLOR" do
      ENV["NO_COLOR"] = "1"
      begin
        Shards::Audit::Config.color_disabled_by_environment?.should be_true
      ensure
        ENV.delete("NO_COLOR")
      end
    end

    it "disables colour when stdout is not a terminal" do
      # The spec runner's stdout is redirected, so this is the piped case.
      ENV.delete("NO_COLOR")
      Shards::Audit::Config.color_disabled_by_environment?.should eq(!STDOUT.tty?)
    end
  end

  describe "cache directory" do
    it "respects XDG_CACHE_HOME" do
      ENV["XDG_CACHE_HOME"] = "/tmp/xdg-cache"
      begin
        Shards::Audit::Config.default_cache_dir.should eq("/tmp/xdg-cache/shards-audit")
      ensure
        ENV.delete("XDG_CACHE_HOME")
      end
    end

    it "falls back to ~/.cache" do
      ENV.delete("XDG_CACHE_HOME")
      Shards::Audit::Config.default_cache_dir
        .should eq(File.join(Path.home.to_s, ".cache", "shards-audit"))
    end
  end
end

describe Shards::Audit::Scanner do
  describe "output determinism" do
    # Crystal's sort is unstable, so severity alone left equally-severe
    # findings ordered by whichever source's fiber finished first.
    it "orders equally severe findings by dependency then id" do
      vulns = [
        Shards::Audit::Vulnerability.new(id: "GHSA-b", dependency_name: "zeta", severity: Shards::Audit::Severity::High),
        Shards::Audit::Vulnerability.new(id: "GHSA-a", dependency_name: "alpha", severity: Shards::Audit::Severity::High),
        Shards::Audit::Vulnerability.new(id: "GHSA-c", dependency_name: "alpha", severity: Shards::Audit::Severity::High),
        Shards::Audit::Vulnerability.new(id: "GHSA-d", dependency_name: "mid", severity: Shards::Audit::Severity::Critical),
      ]

      scanner = Shards::Audit::Scanner.new(Shards::Audit::Config.new)
      ordered = scanner.deduplicate(vulns).map { |v| "#{v.dependency_name}:#{v.id}" }
      ordered.should eq(["mid:GHSA-d", "alpha:GHSA-a", "alpha:GHSA-c", "zeta:GHSA-b"])

      # Shuffled input must produce the identical ordering.
      scanner.deduplicate(vulns.shuffle).map { |v| "#{v.dependency_name}:#{v.id}" }.should eq(ordered)
    end
  end
end
