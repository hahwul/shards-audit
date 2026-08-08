module Shards::Audit
  # Exact CVSS v3.0/v3.1 base-score computation.
  #
  # This replaces an additive heuristic that summed hand-picked weights per
  # metric. That heuristic mis-scored real vectors in both directions, and
  # it scored *any* string starting with "CVSS:" — so a CVSS v4.0 vector,
  # whose impact metrics are named VC/VI/VA rather than C/I/A, contributed
  # nothing from its impact half and landed around 5.0 ("MEDIUM") even for a
  # 9.8 critical. Under `--severity-threshold high` that is a silent false
  # negative, the worst failure mode an audit tool has.
  #
  # v4.0 is deliberately *not* scored here: its base score comes from a
  # MacroVector lookup table, not a closed-form equation, and guessing is
  # what caused the problem above. An unscored vector leaves the severity
  # Unknown, which falls back to the feed's own `severity` string and — per
  # `Severity#meets_threshold?` — always surfaces rather than being hidden.
  module CvssParser
    # Preference rank when an advisory carries several vectors. Higher wins.
    CVSS_V30_RANK = 1
    CVSS_V31_RANK = 2

    AV_WEIGHTS = {"N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2}
    AC_WEIGHTS = {"L" => 0.77, "H" => 0.44}
    UI_WEIGHTS = {"N" => 0.85, "R" => 0.62}
    # Privileges Required is scored differently when Scope is Changed.
    PR_WEIGHTS_UNCHANGED = {"N" => 0.85, "L" => 0.62, "H" => 0.27}
    PR_WEIGHTS_CHANGED   = {"N" => 0.85, "L" => 0.68, "H" => 0.50}
    CIA_WEIGHTS          = {"H" => 0.56, "L" => 0.22, "N" => 0.0}

    # Returns the base score paired with a preference rank, or nil when the
    # vector is absent, malformed, or of a version we do not score exactly.
    private def parse_cvss_score(vector : String) : {Float64, Int32}?
      metrics = parse_vector(vector) || return

      version = metrics["CVSS"]?
      rank = case version
             when "3.1" then CVSS_V31_RANK
             when "3.0" then CVSS_V30_RANK
             else            return
             end

      score = base_score(metrics) || return
      {score, rank}
    end

    private def parse_vector(vector : String) : Hash(String, String)?
      return unless vector.starts_with?("CVSS:")

      metrics = {} of String => String
      vector.split('/') do |part|
        key, _, value = part.partition(':')
        next if value.empty?
        metrics[key] = value
      end
      metrics.empty? ? nil : metrics
    end

    private def base_score(m : Hash(String, String)) : Float64?
      scope_changed = case m["S"]?
                      when "C" then true
                      when "U" then false
                      else          return
                      end

      av = AV_WEIGHTS[m["AV"]?]? || return
      ac = AC_WEIGHTS[m["AC"]?]? || return
      ui = UI_WEIGHTS[m["UI"]?]? || return
      pr_table = scope_changed ? PR_WEIGHTS_CHANGED : PR_WEIGHTS_UNCHANGED
      pr = pr_table[m["PR"]?]? || return

      conf = CIA_WEIGHTS[m["C"]?]? || return
      integ = CIA_WEIGHTS[m["I"]?]? || return
      avail = CIA_WEIGHTS[m["A"]?]? || return

      iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))

      impact = if scope_changed
                 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
               else
                 6.42 * iss
               end

      return 0.0 if impact <= 0

      exploitability = 8.22 * av * ac * pr * ui
      raw = impact + exploitability
      raw *= 1.08 if scope_changed

      roundup(Math.min(raw, 10.0))
    end

    # CVSS v3.1 §7.1 Appendix A: round up to one decimal place, guarding
    # against binary floating-point representation error (a plain
    # `(x * 10).ceil / 10` turns an exact 8.6 into 8.7).
    private def roundup(value : Float64) : Float64
      int_input = (value * 100_000).round.to_i64
      if int_input % 10_000 == 0
        int_input / 100_000.0
      else
        ((int_input // 10_000) + 1) / 10.0
      end
    end
  end
end
