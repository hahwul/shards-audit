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

    EXPIRES_PATTERN = /\A\d{4}-\d{2}-\d{2}\z/

    def self.load(path : String) : ConfigFile
      content = File.read(path)

      # Read through the node tree, not YAML::Any. The core schema turns an
      # unquoted `expires: 2025-12-31` into a Time and `id: 12345` into an
      # Int, and `as_s?` then answers nil for both — so an unquoted expiry
      # date silently produced an ignore entry that never expires, and a
      # numeric id was dropped without a word. Neither warned, because the
      # warning only fired for a String that failed to parse.
      root = YamlNodes.document_root(content)
      return new unless root.is_a?(YAML::Nodes::Mapping)

      ignore = [] of IgnoreEntry
      YamlNodes.sequence_items(YamlNodes.mapping_value(root, "ignore")).each do |entry|
        next unless entry.is_a?(YAML::Nodes::Mapping)
        id = YamlNodes.scalar_value(YamlNodes.mapping_value(entry, "id")).presence
        unless id
          Shards::Audit.stderr.puts "Warning: Ignoring config entry without an 'id'"
          next
        end
        reason = YamlNodes.scalar_value(YamlNodes.mapping_value(entry, "reason"))
        expires = parse_expires(YamlNodes.scalar_value(YamlNodes.mapping_value(entry, "expires")), id)
        ignore << IgnoreEntry.new(id: id, reason: reason, expires: expires)
      end

      severity_threshold = nil
      if sev_str = YamlNodes.scalar_value(YamlNodes.mapping_value(root, "severity_threshold")).presence
        sev = Severity.from_string(sev_str)
        if sev.unknown?
          Shards::Audit.stderr.puts "Warning: Unknown severity_threshold '#{sev_str}' in config, ignoring"
        else
          severity_threshold = sev
        end
      end

      new(ignore: ignore, severity_threshold: severity_threshold)
    end

    # `Time.parse` happily consumes a prefix, so "2025-12-31junk" parsed as
    # 2025-12-31 without complaint. Require the whole value to be a date.
    private def self.parse_expires(value : String?, id : String) : Time?
      return unless value = value.presence
      unless value.matches?(EXPIRES_PATTERN)
        Shards::Audit.stderr.puts "Warning: Invalid expires date '#{value}' for ignore entry #{id}, ignoring expiry"
        return
      end
      Time.parse(value, "%Y-%m-%d", Time::Location::UTC)
    rescue
      Shards::Audit.stderr.puts "Warning: Invalid expires date '#{value}' for ignore entry #{id}, ignoring expiry"
      nil
    end
  end
end
