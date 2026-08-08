require "yaml"

module Shards::Audit
  # Helpers for reading YAML through its node tree instead of `YAML.parse`.
  #
  # `YAML::Any` applies the core schema, which silently retypes scalars that
  # a config or lockfile means as text: `version: 1.0` becomes a Float,
  # `commit: 1234567` an Int, `expires: 2025-12-31` a Time, `id: 12345` an
  # Int. Every one of those makes `as_s?` return nil, and the calling code
  # then treats a value the user clearly wrote as simply absent — a
  # dependency never queried, or a suppression that never expires.
  #
  # Nodes keep the literal text, so what the file says is what we read.
  module YamlNodes
    # Plain (unquoted) spellings of YAML null. Quoted forms are real strings.
    NULL_SCALARS = {"", "~", "null", "Null", "NULL"}

    def self.document_root(content : String) : YAML::Nodes::Node?
      YAML::Nodes.parse(content).nodes.first?
    end

    def self.mapping_value(mapping : YAML::Nodes::Mapping, key : String) : YAML::Nodes::Node?
      mapping.each do |k, v|
        return v if scalar_value(k) == key
      end
      nil
    end

    # The scalar's literal text, or nil when the node is absent, is not a
    # scalar, or spells an unquoted null.
    def self.scalar_value(node : YAML::Nodes::Node?) : String?
      return unless node.is_a?(YAML::Nodes::Scalar)
      value = node.value
      return if node.style.plain? && NULL_SCALARS.includes?(value)
      value
    end

    def self.sequence_items(node : YAML::Nodes::Node?) : Array(YAML::Nodes::Node)
      node.is_a?(YAML::Nodes::Sequence) ? node.nodes : [] of YAML::Nodes::Node
    end
  end
end
