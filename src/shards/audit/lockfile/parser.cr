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
      # Parsed through YAML::Nodes rather than YAML.parse so scalars keep
      # their *written* text. The core schema types an unquoted `version: 1.0`
      # as a float and `commit: 1234567` as an integer, and `YAML::Any#as_s?`
      # then returns nil for both. A dependency with neither version nor
      # commit contributes no OSV query at all, so it was silently never
      # checked — and two-component versions are written unquoted by shards.
      root = begin
        YamlNodes.document_root(content)
      rescue ex : YAML::ParseException
        raise ParseError.new("Invalid shard.lock YAML: #{ex.message}")
      end

      unless root.is_a?(YAML::Nodes::Mapping)
        raise ParseError.new("Invalid shard.lock format: expected a mapping at the top level")
      end

      shards = YamlNodes.mapping_value(root, "shards")
      unless shards
        raise ParseError.new("Invalid shard.lock format: missing 'shards' key")
      end

      unless shards.is_a?(YAML::Nodes::Mapping)
        raise ParseError.new("Invalid shard.lock format: 'shards' must be a mapping")
      end

      dependencies = [] of Dependency
      skipped_deps = [] of String

      shards.each do |name_node, info|
        dep_name = YamlNodes.scalar_value(name_node)
        next unless dep_name
        next if dep_name.empty?

        # A shard entry that is not a mapping (a bare string, a list, null).
        unless info.is_a?(YAML::Nodes::Mapping)
          skipped_deps << dep_name
          next
        end

        git_url = YamlNodes.scalar_value(YamlNodes.mapping_value(info, "git")).presence
        unless git_url
          skipped_deps << dep_name
          next
        end

        version = YamlNodes.scalar_value(YamlNodes.mapping_value(info, "version"))
        commit = YamlNodes.scalar_value(YamlNodes.mapping_value(info, "commit"))

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
