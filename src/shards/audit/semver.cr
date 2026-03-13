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
      s = str.lstrip('v')
      return nil if s.empty?

      pre = nil
      if dash = s.index('-')
        pre = s[(dash + 1)..]
        s = s[0...dash]
      end

      parts = s.split('.')
      return nil if parts.size < 1 || parts.size > 3

      major = parts[0].to_i32?
      return nil unless major

      minor = parts.size >= 2 ? parts[1].to_i32? : 0
      return nil if parts.size >= 2 && minor.nil?
      minor ||= 0

      patch = parts.size >= 3 ? parts[2].to_i32? : 0
      return nil if parts.size >= 3 && patch.nil?
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
        p1 <=> p2
      elsif p1.nil? && p2.nil?
        0
      elsif p1.nil?
        1
      else
        -1
      end
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

    def initialize(@introduced = nil, @fixed = nil)
    end

    def includes?(version : Semver) : Bool
      if intro = introduced
        return false if version < intro
      end
      if fix = fixed
        return false if version >= fix
      end
      true
    end
  end

  module SemverRangeParser
    def self.parse_osv_events(events : Array) : Array(SemverRange)
      ranges = [] of SemverRange
      introduced : Semver? = nil

      events.each do |event|
        if intro_str = event["introduced"]?.try(&.as_s)
          introduced = if intro_str == "0"
                         Semver.new(0, 0, 0)
                       else
                         Semver.parse(intro_str)
                       end
        elsif fixed_str = event["fixed"]?.try(&.as_s)
          fixed = Semver.parse(fixed_str)
          ranges << SemverRange.new(introduced: introduced, fixed: fixed)
          introduced = nil
        elsif event["last_affected"]?.try(&.as_s)
          # last_affected means no fix yet
          ranges << SemverRange.new(introduced: introduced, fixed: nil)
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
          # > X.Y.Z means introduced at next version; approximate with same value
          introduced = ver
        when "<"
          fixed = ver
        when "<="
          # <= X.Y.Z means fixed is one above; approximate with next patch
          fixed = Semver.new(ver.major, ver.minor, ver.patch + 1)
        when "="
          introduced = ver
          fixed = Semver.new(ver.major, ver.minor, ver.patch + 1)
        end
      end

      # If we only got a lower bound, it means still vulnerable
      return [] of SemverRange unless introduced || fixed
      [SemverRange.new(introduced: introduced, fixed: fixed)]
    end
  end
end
