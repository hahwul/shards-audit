module Shards::Audit
  struct Semver
    include Comparable(Semver)

    getter major : Int32
    getter minor : Int32
    getter patch : Int32
    getter prerelease : String?

    def initialize(@major, @minor, @patch, @prerelease = nil)
    end

    def self.parse(str : String) : Semver?
      s = str.strip
      # A single optional `v` prefix, as shipped by git tags. `lstrip('v')`
      # previously ate every leading `v`, so the nonsense "vvv1.0.0" parsed
      # as 1.0.0.
      s = s[1..] if s.starts_with?('v')
      return if s.empty?

      # SemVer 2.0.0 §10: build metadata is ignored for precedence, so drop
      # it. Keeping it made `1.2.3+git.abc` unparseable, and an unparseable
      # bound in an OSV range silently degraded to "no bound" — i.e. a range
      # matching every version.
      if plus = s.index('+')
        s = s[0...plus]
      end

      pre = nil
      if dash = s.index('-')
        pre = s[(dash + 1)..]
        s = s[0...dash]
      end

      parts = s.split('.')
      return if parts.size < 1 || parts.size > 3

      major = parts[0].to_i32?
      return unless major

      minor = parts.size >= 2 ? parts[1].to_i32? : 0
      return if parts.size >= 2 && minor.nil?
      minor ||= 0

      patch = parts.size >= 3 ? parts[2].to_i32? : 0
      return if parts.size >= 3 && patch.nil?
      patch ||= 0

      new(major, minor, patch, pre.presence)
    end

    def <=>(other : Semver) : Int32
      c = major <=> other.major
      return c unless c == 0
      c = minor <=> other.minor
      return c unless c == 0
      c = patch <=> other.patch
      return c unless c == 0

      # No prerelease > has prerelease (1.0.0 > 1.0.0-rc1)
      p1 = prerelease
      p2 = other.prerelease
      if p1 && p2
        Semver.compare_prerelease(p1, p2)
      elsif p1.nil? && p2.nil?
        0
      elsif p1.nil?
        1
      else
        -1
      end
    end

    # Compare two SemVer 2.0.0 prerelease strings dot-separated identifier
    # by identifier. Numeric identifiers compare numerically; non-numeric
    # identifiers compare lexically; numeric identifiers always have lower
    # precedence than non-numeric. A larger set of identifiers has higher
    # precedence than a smaller set when all leading ones are equal.
    #
    # The previous implementation used a raw String#<=> which produced
    # `"rc10" < "rc2"` (lexical), classifying genuinely vulnerable
    # prerelease versions as "already fixed" against advisories whose
    # boundary lay on a prerelease.
    def self.compare_prerelease(p1 : String, p2 : String) : Int32
      ids1 = p1.split('.')
      ids2 = p2.split('.')

      [ids1.size, ids2.size].min.times do |i|
        a = ids1[i]
        b = ids2[i]
        a_num = a.to_i64?
        b_num = b.to_i64?

        cmp = if a_num && b_num
                a_num <=> b_num
              elsif a_num
                -1
              elsif b_num
                1
              else
                a <=> b
              end
        return cmp unless cmp == 0
      end

      ids1.size <=> ids2.size
    end

    def to_s(io : IO) : Nil
      io << major << '.' << minor << '.' << patch
      if pre = prerelease
        io << '-' << pre
      end
    end
  end

  struct SemverRange
    getter introduced : Semver?
    getter fixed : Semver?
    getter introduced_exclusive : Bool
    getter fixed_inclusive : Bool

    def initialize(@introduced = nil, @fixed = nil, @introduced_exclusive = false, @fixed_inclusive = false)
    end

    # Human/machine readable rendering of the bounds, e.g. ">=1.0.0 <2.0.0".
    # Reports omit the inclusivity flags otherwise, which makes an inclusive
    # upper bound look exclusive.
    def to_constraint : String
      parts = [] of String
      if intro = introduced
        parts << "#{introduced_exclusive ? ">" : ">="}#{intro}"
      end
      if fix = fixed
        parts << "#{fixed_inclusive ? "<=" : "<"}#{fix}"
      end
      parts.empty? ? "*" : parts.join(" ")
    end

    def includes?(version : Semver) : Bool
      if intro = introduced
        if introduced_exclusive
          return false if version <= intro
        else
          return false if version < intro
        end
      end
      if fix = fixed
        if fixed_inclusive
          return false if version > fix
        else
          return false if version >= fix
        end
      end
      true
    end
  end

  module SemverRangeParser
    # `events` are OSV range events. Values are read with `as_s?` so a
    # null or non-string event value yields nil instead of raising a
    # TypeCastError deep inside a scanning fiber.
    def self.parse_osv_events(events : Array(JSON::Any)) : Array(SemverRange)
      ranges = [] of SemverRange
      introduced : Semver? = nil

      events.each do |event|
        next unless event.as_h?

        if intro_str = event["introduced"]?.try(&.as_s?)
          introduced = if intro_str == "0"
                         Semver.new(0, 0, 0)
                       else
                         Semver.parse(intro_str)
                       end
        elsif fixed_str = event["fixed"]?.try(&.as_s?)
          fixed = Semver.parse(fixed_str)
          ranges << SemverRange.new(introduced: introduced, fixed: fixed)
          introduced = nil
        elsif last_str = event["last_affected"]?.try(&.as_s?)
          # last_affected is an INCLUSIVE upper bound (OSV semantics): versions
          # up to and including last_affected are vulnerable, versions above it
          # are not. Model it as `fixed: last_affected` with fixed_inclusive.
          last = Semver.parse(last_str)
          ranges << SemverRange.new(introduced: introduced, fixed: last, fixed_inclusive: true)
          introduced = nil
        end
      end

      # Trailing introduced with no fixed = still vulnerable
      if introduced
        ranges << SemverRange.new(introduced: introduced, fixed: nil)
      end

      ranges
    end

    def self.parse_github_range(range_str : String) : Array(SemverRange)
      return [] of SemverRange if range_str.strip.empty?

      constraints = range_str.split(',').map(&.strip).reject(&.empty?)
      introduced : Semver? = nil
      fixed : Semver? = nil

      introduced_exclusive = false
      fixed_inclusive = false

      constraints.each do |constraint|
        parts = constraint.split(/\s+/, 2)
        next if parts.size != 2

        op = parts[0]
        ver = Semver.parse(parts[1])
        next unless ver

        case op
        when ">="
          introduced = ver
        when ">"
          introduced = ver
          introduced_exclusive = true
        when "<"
          fixed = ver
        when "<="
          fixed = ver
          fixed_inclusive = true
        when "="
          introduced = ver
          fixed = ver
          fixed_inclusive = true
        end
      end

      # If we only got a lower bound, it means still vulnerable
      return [] of SemverRange unless introduced || fixed
      [SemverRange.new(introduced: introduced, fixed: fixed,
        introduced_exclusive: introduced_exclusive, fixed_inclusive: fixed_inclusive)]
    end
  end
end
