require "yaml"

module Shards::Audit
  class LockfileParser
    class ParseError < Exception; end

    MAX_LOCKFILE_SIZE = 5 * 1024 * 1024 # 5MB

    record ParseResult, dependencies : Array(Dependency), skipped_deps : Array(String)

    def self.parse(path : String) : ParseResult
      unless File.exists?(path)
        raise ParseError.new("Lockfile not found: #{path}")
      end

      file_size = File.size(path)
      if file_size > MAX_LOCKFILE_SIZE
        raise ParseError.new("Lockfile too large: #{file_size} bytes (max #{MAX_LOCKFILE_SIZE})")
      end

      content = begin
        File.read(path)
      rescue ex : IO::Error
        # File.exists? above is only a hint: the file can vanish or be
        # unreadable (permissions, a directory, a dangling symlink) between
        # the check and the read.
        raise ParseError.new("Cannot read lockfile #{path}: #{ex.message}")
      end

      parse_content(content)
    end

    def self.parse_content(content : String) : ParseResult
      # Every malformed-input path must surface as ParseError. An escaping
      # YAML::ParseException reached `main` as an unhandled exception, which
      # printed a backtrace and exited 1 — the exit code that means
      # "vulnerabilities found", so a broken lockfile looked like a failed
      # audit to CI instead of a tool error (exit 2).
      data = begin
        YAML.parse(content)
      rescue ex : YAML::ParseException
        raise ParseError.new("Invalid shard.lock YAML: #{ex.message}")
      end

      root = data.as_h?
      unless root
        raise ParseError.new("Invalid shard.lock format: expected a mapping at the top level")
      end

      shards = root["shards"]?
      unless shards
        raise ParseError.new("Invalid shard.lock format: missing 'shards' key")
      end

      shards_hash = shards.as_h?
      unless shards_hash
        raise ParseError.new("Invalid shard.lock format: 'shards' must be a mapping")
      end

      dependencies = [] of Dependency
      skipped_deps = [] of String

      shards_hash.each do |name, info|
        dep_name = name.as_s?
        next unless dep_name
        next if dep_name.empty?

        # A shard entry that is not a mapping (a bare string, a list, null)
        # used to raise "Expected Array or Hash" straight out of YAML::Any.
        info_hash = info.as_h?
        unless info_hash
          skipped_deps << dep_name
          next
        end

        git_url = info_hash["git"]?.try(&.as_s?).presence
        unless git_url
          skipped_deps << dep_name
          next
        end

        version = info_hash["version"]?.try(&.as_s?)
        commit = info_hash["commit"]?.try(&.as_s?)

        # Some lockfiles store version as "X.Y.Z+git.commit.HASH"
        if version && version.includes?("+git.commit.")
          parts = version.split("+git.commit.")
          version = parts[0]
          commit ||= parts[1]?
        end

        dependencies << Dependency.new(
          name: dep_name,
          git_url: git_url,
          version: version.presence,
          commit: commit.presence,
        )
      end

      ParseResult.new(dependencies: dependencies, skipped_deps: skipped_deps)
    end
  end
end
