module Shards::Audit
  module CvssParser
    # Simplified CVSS v3 scoring based on impact metrics.
    # This is an approximation used as a fallback when the advisory source
    # does not provide a pre-computed numeric score. The official CVSS v3.1
    # algorithm uses non-linear formulas; this linear heuristic provides
    # a reasonable severity classification for triage purposes.
    private def parse_cvss_score(vector : String) : Float64?
      return nil unless vector.starts_with?("CVSS:")

      parts = vector.split("/")
      return nil if parts.size < 2

      score = 0.0
      parts.each do |part|
        case part
        when "AV:N" then score += 2.0
        when "AV:A" then score += 1.5
        when "AV:L" then score += 1.0
        when "AV:P" then score += 0.5
        when "AC:L" then score += 1.0
        when "AC:H" then score += 0.5
        when "PR:N" then score += 1.0
        when "PR:L" then score += 0.5
        when "UI:N" then score += 1.0
        when "UI:R" then score += 0.5
        when "S:C"  then score += 1.0
        when "S:U"  then score += 0.5
        when "C:H"  then score += 1.5
        when "C:L"  then score += 0.5
        when "I:H"  then score += 1.5
        when "I:L"  then score += 0.5
        when "A:H"  then score += 1.0
        when "A:L"  then score += 0.5
        end
      end

      score.clamp(0.0, 10.0)
    end
  end
end
