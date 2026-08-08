require "json"

module Shards::Audit
  # Total (never-raising) accessors for advisory JSON.
  #
  # `JSON::Any#[]?` only tolerates a *missing* key. It raises when the
  # receiver is not a Hash ("Expected Hash for #[]?(key : String), not
  # String"), and the `as_s`/`as_a`/`as_h` casts raise `TypeCastError` on a
  # JSON `null` — which is a *present* key, so `#[]?` happily returns it.
  #
  # Both are routine in real advisory feeds: GitHub sends `"cve_id": null`
  # for advisories without a CVE and `"vulnerabilities": null` for some
  # entries, and OSV omits or nulls `summary`. Because parsing runs inside
  # spawned fibers, a raise there did not merely lose one advisory: the
  # fiber died before sending on its channel and the scan deadlocked.
  #
  # These helpers return nil for "absent, null, or wrong type" uniformly so
  # a malformed field degrades one value instead of the whole scan.
  module JsonAccess
    # Walks a chain of object keys, stopping at the first level that is
    # missing or is not a JSON object.
    private def dig(value : JSON::Any?, *keys : String) : JSON::Any?
      current = value
      keys.each do |key|
        return unless node = current
        return unless hash = node.as_h?
        current = hash[key]?
      end
      current
    end

    # Scrubbed because advisory text reaches us verbatim from the network
    # and JSON::Parser preserves invalid UTF-8 bytes. Handing those to
    # `to_yaml` aborts the process outright — not a catchable exception, and
    # the abort status is 1, which is the "vulnerabilities found" code. JSON
    # and SARIF merely emitted bytes no conforming parser would accept.
    private def dig_s(value : JSON::Any?, *keys : String) : String?
      dig(value, *keys).try(&.as_s?).try(&.scrub)
    end

    private def dig_a(value : JSON::Any?, *keys : String) : Array(JSON::Any)?
      dig(value, *keys).try(&.as_a?)
    end

    private def dig_h(value : JSON::Any?, *keys : String) : Hash(String, JSON::Any)?
      dig(value, *keys).try(&.as_h?)
    end

    # Accepts both JSON numbers and numeric strings, since advisory feeds
    # are inconsistent about quoting CVSS scores.
    private def dig_f(value : JSON::Any?, *keys : String) : Float64?
      node = dig(value, *keys) || return
      node.as_f? || node.as_i?.try(&.to_f) || node.as_s?.try(&.to_f?)
    end
  end
end
