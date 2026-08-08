require "../../spec_helper"
require "file_utils"

private def run_cli(args : Array(String)) : {Int32, String, String}
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

private def load_config(yaml : String) : Shards::Audit::ConfigFile
  path = File.tempname("shards-audit-cfg")
  File.write(path, yaml)
  begin
    Shards::Audit::ConfigFile.load(path)
  ensure
    File.delete(path) rescue nil
  end
end

private def lock(body : String) : Shards::Audit::LockfileParser::ParseResult
  Shards::Audit::LockfileParser.parse_content(body)
end

describe Shards::Audit::LockfileParser do
  describe "scalars the YAML core schema would retype" do
    # `YAML::Any` turns an unquoted `version: 1.0` into a Float and
    # `commit: 1234567` into an Int; `as_s?` then answers nil for both. A
    # dependency with neither version nor commit contributes no OSV query at
    # all, so it was silently never checked.
    it "keeps a two-component version" do
      result = lock("shards:\n  d:\n    git: https://github.com/o/d.git\n    version: 1.0\n")
      result.dependencies[0].version.should eq("1.0")
    end

    it "keeps a trailing zero rather than rounding it away" do
      result = lock("shards:\n  d:\n    git: https://github.com/o/d.git\n    version: 1.10\n")
      result.dependencies[0].version.should eq("1.10")
    end

    it "keeps an integer-looking version" do
      lock("shards:\n  d:\n    git: https://github.com/o/d.git\n    version: 1\n")
        .dependencies[0].version.should eq("1")
    end

    it "keeps an all-digit commit" do
      lock("shards:\n  d:\n    git: https://github.com/o/d.git\n    commit: 1234567\n")
        .dependencies[0].commit.should eq("1234567")
    end

    it "still treats an unquoted null as absent" do
      result = lock("shards:\n  d:\n    git: https://github.com/o/d.git\n    version: ~\n")
      result.dependencies[0].version.should be_nil
    end

    it "treats a quoted 'null' as a real string" do
      result = lock("shards:\n  d:\n    git: https://github.com/o/d.git\n    version: \"null\"\n")
      result.dependencies[0].version.should eq("null")
    end

    it "actually produces an OSV query for such a dependency" do
      dep = lock("shards:\n  d:\n    git: https://github.com/o/d.git\n    version: 1.0\n").dependencies[0]
      probe = OsvQueryProbe.new
      probe.queries_for(dep).should_not be_empty
    end
  end
end

private class OsvQueryProbe < Shards::Audit::OsvClient
  def queries_for(dep : Shards::Audit::Dependency)
    build_dep_queries(dep)
  end
end

describe Shards::Audit::ConfigFile do
  describe "an expiry date the YAML schema resolves to a Time" do
    # Unquoted, `expires: 2020-01-01` becomes a Time, `as_s?` returns nil,
    # and the entry silently became a suppression that never expires — with
    # no warning, because the warning only fired for an unparseable String.
    it "expires an unquoted past date" do
      entry = load_config("ignore:\n  - id: GHSA-OLD\n    expires: 2020-01-01\n").ignore[0]
      entry.expires.should_not be_nil
      entry.active?.should be_false
    end

    it "expires a quoted past date" do
      load_config("ignore:\n  - id: GHSA-OLD\n    expires: \"2020-01-01\"\n").ignore[0]
        .active?.should be_false
    end

    it "keeps a future date active" do
      load_config("ignore:\n  - id: GHSA-NEW\n    expires: 2999-01-01\n").ignore[0]
        .active?.should be_true
    end

    it "rejects a date with trailing garbage instead of accepting the prefix" do
      Shards::Audit.stderr = IO::Memory.new
      begin
        entry = load_config("ignore:\n  - id: G\n    expires: \"2025-12-31junk\"\n").ignore[0]
        entry.expires.should be_nil
        Shards::Audit.stderr.to_s.should contain("Invalid expires date")
      ensure
        Shards::Audit.stderr = SPEC_STDERR
      end
    end
  end

  describe "other retyped scalars" do
    it "keeps a numeric ignore id" do
      load_config("ignore:\n  - id: 12345\n").ignore.map(&.id).should eq(["12345"])
    end

    it "warns about an unknown severity threshold instead of dropping it silently" do
      Shards::Audit.stderr = IO::Memory.new
      begin
        load_config("severity_threshold: hgih\n").severity_threshold.should be_nil
        Shards::Audit.stderr.to_s.should contain("Unknown severity_threshold")
      ensure
        Shards::Audit.stderr = SPEC_STDERR
      end
    end

    it "still reads a valid threshold" do
      load_config("severity_threshold: medium\n").severity_threshold
        .should eq(Shards::Audit::Severity::Medium)
    end
  end
end

describe Shards::Audit::Cache do
  describe "symlink handling in #set" do
    # `get` refused to read through a symlink but `set` wrote through one,
    # so the protection covered only half the operation.
    it "refuses to write through a symlinked cache file" do
      root = File.tempname("shards-audit-sym")
      Dir.mkdir_p(File.join(root, "base"))
      begin
        victim = File.join(root, "outside.txt")
        File.write(victim, "ORIGINAL")
        File.symlink(victim, File.join(root, "base", "evil.json"))

        Shards::Audit::Cache.new(File.join(root, "base")).set("evil.json", "PWNED")
        File.read(victim).should eq("ORIGINAL")
      ensure
        FileUtils.rm_rf(root)
      end
    end

    it "refuses to write through a symlinked cache directory and leaves its mode alone" do
      root = File.tempname("shards-audit-sym")
      Dir.mkdir_p(File.join(root, "base"))
      begin
        outside = File.join(root, "outside_dir")
        Dir.mkdir_p(outside)
        File.chmod(outside, 0o755)
        File.symlink(outside, File.join(root, "base", "github"))

        Shards::Audit::Cache.new(File.join(root, "base")).set("github/o_r.json", "LEAKED")
        File.exists?(File.join(outside, "o_r.json")).should be_false
        File.info(outside).permissions.should eq(File::Permissions.new(0o755))
      ensure
        FileUtils.rm_rf(root)
      end
    end
  end

  describe "key collisions" do
    it "does not serve one key's value for another that sanitises the same" do
      dir = File.tempname("shards-audit-collide")
      Dir.mkdir_p(dir)
      begin
        cache = Shards::Audit::Cache.new(dir)
        cache.set("github/a_b.json", "VALUE_A")
        cache.get("github/a:b.json").should be_nil

        cache.set("github/a:b.json", "VALUE_B")
        cache.get("github/a:b.json").should eq("VALUE_B")
        cache.get("github/a_b.json").should eq("VALUE_A")
      ensure
        FileUtils.rm_rf(dir)
      end
    end
  end

  describe "an empty base directory" do
    it "writes nothing rather than scattering files through the working directory" do
      dir = File.tempname("shards-audit-empty")
      Dir.mkdir_p(dir)
      begin
        Dir.cd(dir) { Shards::Audit::Cache.new("").set("osv/vulns/X.json", "x") }
        File.exists?(File.join(dir, "osv", "vulns", "X.json")).should be_false
      ensure
        FileUtils.rm_rf(dir)
      end
    end
  end
end

describe Shards::Audit::CLI do
  describe "unexpected positional arguments" do
    # OptionParser discards leftovers, so `shards-audit real/shard.lock`
    # scanned ./shard.lock instead and CI got a green pass for a file that
    # was never read.
    it "rejects a bare path instead of silently scanning the default" do
      exit_code, _, stderr = run_cli(["--no-config", "some/shard.lock"])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
      stderr.should contain("Unexpected argument")
      stderr.should contain("-p PATH")
    end

    it "still accepts a correct invocation" do
      exit_code, _, _ = run_cli([
        "--no-config", "-p", File.join(FIXTURES_PATH, "shard.lock.empty"),
      ])
      exit_code.should eq(Shards::Audit::CLI::EXIT_CLEAN)
    end
  end

  describe "empty flag values" do
    it "rejects an empty --path" do
      exit_code, _, stderr = run_cli(["--no-config", "--path", ""])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
      stderr.should contain("--path requires a non-empty value")
    end

    it "rejects an empty --cache-dir" do
      exit_code, _, stderr = run_cli(["--no-config", "--cache-dir", ""])
      exit_code.should eq(Shards::Audit::CLI::EXIT_ERROR)
      stderr.should contain("--cache-dir requires a non-empty value")
    end
  end

  describe "diagnostic output" do
    # CLI.stderr and Shards::Audit.stderr were independent sinks, so
    # redirecting one still let the other escape to the terminal.
    it "routes library diagnostics through the same sink" do
      captured = IO::Memory.new
      Shards::Audit::CLI.stderr = captured
      begin
        Shards::Audit.stderr.should be(captured)
        Shards::Audit.stderr.puts "from the library"
        captured.to_s.should contain("from the library")
      ensure
        Shards::Audit::CLI.stderr = SPEC_STDERR
      end
    end
  end
end

describe Shards::Audit::TableFormatter do
  describe "the all-clear message" do
    it "is unqualified when every source answered" do
      io = IO::Memory.new
      Shards::Audit::TableFormatter.new(no_color: true).format(Shards::Audit::AuditResult.new, io)
      io.to_s.should contain("No vulnerabilities found!")
    end

    # Promising a clean bill of health while half the sources never answered
    # is the one claim this tool must not make.
    it "is qualified when a source failed" do
      result = Shards::Audit::AuditResult.new
      result.errors << "GitHub scan: all 3 GitHub lookups failed"
      io = IO::Memory.new
      Shards::Audit::TableFormatter.new(no_color: true).format(result, io)
      io.to_s.should contain("sources that responded")
      io.to_s.should_not contain("No vulnerabilities found!")
      io.to_s.should contain("all 3 GitHub lookups failed")
    end
  end
end

describe "advisory text that is not valid UTF-8" do
  # JSON::Parser preserves invalid bytes. Handing those to `to_yaml` aborts
  # the process — not a catchable exception — with status 1, the code that
  # means "vulnerabilities found".
  it "is scrubbed at ingestion so every format survives" do
    body = String.new(Bytes[
      123, 34, 105, 100, 34, 58, 34, 79, 83, 86, 45, 49, 34, 44,
      34, 115, 117, 109, 109, 97, 114, 121, 34, 58, 34, 65, 255, 254, 66, 34, 125,
    ])
    body.valid_encoding?.should be_false

    vuln = OsvTextProbe.new.parse(body).not_nil!
    vuln.summary.valid_encoding?.should be_true

    result = Shards::Audit::AuditResult.new
    result.vulnerabilities = [vuln]
    result.vulnerabilities_found = 1

    yaml_io = IO::Memory.new
    Shards::Audit::YamlFormatter.new.format(result, yaml_io)
    yaml_io.to_s.valid_encoding?.should be_true

    json_io = IO::Memory.new
    Shards::Audit::JsonFormatter.new.format(result, json_io)
    JSON.parse(json_io.to_s)["vulnerabilities"][0]["id"].as_s.should eq("OSV-1")
  end
end

private class OsvTextProbe
  include Shards::Audit::OsvParser

  def parse(body : String)
    parse_vulnerability(body)
  end
end
