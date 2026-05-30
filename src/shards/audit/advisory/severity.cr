module Shards::Audit
  enum Severity
    Critical
    High
    Medium
    Low
    Unknown

    def self.from_cvss(score : Float64) : Severity
      case score
      when 9.0..10.0 then Critical
      when 7.0...9.0 then High
      when 4.0...7.0 then Medium
      when 0.1...4.0 then Low
      else                Unknown
      end
    end

    def self.from_string(value : String) : Severity
      case value.downcase
      when "critical" then Critical
      when "high"     then High
      when "medium"   then Medium
      when "moderate" then Medium
      when "low"      then Low
      else                 Unknown
      end
    end

    def color_code : String
      case self
      when Critical then "\e[91m" # bright red
      when High     then "\e[31m" # red
      when Medium   then "\e[33m" # yellow
      when Low      then "\e[36m" # cyan
      else               "\e[37m" # white
      end
    end

    def label : String
      case self
      when Critical then "CRITICAL"
      when High     then "HIGH"
      when Medium   then "MEDIUM"
      when Low      then "LOW"
      else               "UNKNOWN"
      end
    end

    def priority : Int32
      case self
      when Critical then 4
      when High     then 3
      when Medium   then 2
      when Low      then 1
      else               0
      end
    end

    def meets_threshold?(threshold : Severity) : Bool
      # An Unknown severity means we couldn't determine how bad the
      # advisory is. For a security audit, silently dropping it below a
      # threshold would be a false negative, so an unknown-severity finding
      # always passes any threshold — better to surface it and let a human
      # judge than to hide it.
      return true if self == Severity::Unknown
      priority >= threshold.priority
    end
  end
end
