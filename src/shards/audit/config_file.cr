require "yaml"

module Shards::Audit
  struct IgnoreEntry
    getter id : String
    getter reason : String?
    getter expires : Time?

    def initialize(@id, @reason = nil, @expires = nil)
    end

    def active? : Bool
      return true unless exp = expires
      Time.utc < exp
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

      return new if yaml.raw.nil?

      ignore = [] of IgnoreEntry
      if ignore_list = yaml["ignore"]?.try(&.as_a?)
        ignore_list.each do |entry|
          id = entry["id"]?.try(&.as_s?) || next
          reason = entry["reason"]?.try(&.as_s?)
          expires = nil
          if exp_str = entry["expires"]?.try(&.as_s?)
            expires = Time.parse(exp_str, "%Y-%m-%d", Time::Location::UTC) rescue nil
          end
          ignore << IgnoreEntry.new(id: id, reason: reason, expires: expires)
        end
      end

      severity_threshold = nil
      if sev_str = yaml["severity_threshold"]?.try(&.as_s?)
        sev = Severity.from_string(sev_str)
        severity_threshold = sev unless sev.unknown?
      end

      new(ignore: ignore, severity_threshold: severity_threshold)
    end
  end
end
