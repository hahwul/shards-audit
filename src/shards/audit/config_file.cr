require "yaml"

module Shards::Audit
  struct IgnoreEntry
    getter id : String
    getter reason : String?
    getter expires : Time?

    def initialize(@id, @reason = nil, @expires = nil)
    end

    # `expires` is a calendar date, so it stays active through the *whole*
    # of that day. Comparing against the parsed midnight made
    # `expires: 2025-12-31` lapse at 00:00 on the 31st — a day early, which
    # surfaces a suppressed finding sooner than the user asked for.
    def active? : Bool
      return true unless exp = expires
      Time.utc < exp + 1.day
    end
  end

  class ConfigFile
    getter ignore : Array(IgnoreEntry)
    getter severity_threshold : Severity?

    CONFIG_FILENAME = ".shards-audit.yml"

    def initialize(@ignore = [] of IgnoreEntry, @severity_threshold = nil)
    end

    def self.find(dir : String = ".") : String?
      current = File.expand_path(dir)
      loop do
        path = File.join(current, CONFIG_FILENAME)
        return path if File.exists?(path)
        parent = File.dirname(current)
        break if parent == current
        current = parent
      end

      # Check home directory
      home_path = File.join(Path.home.to_s, CONFIG_FILENAME)
      return home_path if File.exists?(home_path)

      nil
    end

    def self.load(path : String) : ConfigFile
      content = File.read(path)
      yaml = YAML.parse(content)

      # `YAML::Any#[]?` raises on a non-mapping receiver, so a config file
      # that is empty, a bare scalar, or a top-level list must be rejected
      # by shape rather than indexed into.
      root = yaml.as_h? || return new

      ignore = [] of IgnoreEntry
      if ignore_list = root["ignore"]?.try(&.as_a?)
        ignore_list.each do |entry|
          entry_hash = entry.as_h? || next
          id = entry_hash["id"]?.try(&.as_s?) || next
          reason = entry_hash["reason"]?.try(&.as_s?)
          expires = nil
          if exp_str = entry_hash["expires"]?.try(&.as_s?)
            begin
              expires = Time.parse(exp_str, "%Y-%m-%d", Time::Location::UTC)
            rescue
              Shards::Audit.stderr.puts "Warning: Invalid expires date '#{exp_str}' for ignore entry #{id}, ignoring expiry"
            end
          end
          ignore << IgnoreEntry.new(id: id, reason: reason, expires: expires)
        end
      end

      severity_threshold = nil
      if sev_str = root["severity_threshold"]?.try(&.as_s?)
        sev = Severity.from_string(sev_str)
        severity_threshold = sev unless sev.unknown?
      end

      new(ignore: ignore, severity_threshold: severity_threshold)
    end
  end
end
