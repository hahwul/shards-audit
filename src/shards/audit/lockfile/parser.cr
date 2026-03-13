require "yaml"

module Shards::Audit
  class LockfileParser
    class ParseError < Exception; end

    MAX_LOCKFILE_SIZE = 5 * 1024 * 1024 # 5MB

    def self.parse(path : String) : Array(Dependency)
      unless File.exists?(path)
        raise ParseError.new("Lockfile not found: #{path}")
      end

      file_size = File.size(path)
      if file_size > MAX_LOCKFILE_SIZE
        raise ParseError.new("Lockfile too large: #{file_size} bytes (max #{MAX_LOCKFILE_SIZE})")
      end

      content = File.read(path)
      parse_content(content)
    end

    def self.parse_content(content : String) : Array(Dependency)
      data = YAML.parse(content)

      unless data["shards"]?
        raise ParseError.new("Invalid shard.lock format: missing 'shards' key")
      end

      shards = data["shards"]
      dependencies = [] of Dependency

      shards.as_h.each do |name, info|
        dep_name = name.as_s
        next if dep_name.empty?

        git_url = info["git"]?.try(&.as_s)
        next unless git_url

        version = info["version"]?.try(&.as_s)
        commit = info["commit"]?.try(&.as_s)

        # Some lockfiles store version as "X.Y.Z+git.commit.HASH"
        if version && version.includes?("+git.commit.")
          parts = version.split("+git.commit.")
          version = parts[0]
          commit ||= parts[1]?
        end

        dependencies << Dependency.new(
          name: dep_name,
          git_url: git_url,
          version: version,
          commit: commit,
        )
      end

      dependencies
    end
  end
end
