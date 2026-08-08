require "json"

module Shards::Audit
  module OsvParser
    include CvssParser
    include JsonAccess

    # OSV `affected[].ranges[].type` values whose event values are version
    # strings. `GIT` ranges carry *commit hashes* instead, which must never
    # be fed to the SemVer comparator.
    VERSION_RANGE_TYPES = {"SEMVER", "ECOSYSTEM"}

    # Map querybatch results back to the originating dependencies. The OSV
    # spec promises results are returned in the same order as queries —
    # validate that contract so a backend change cannot silently misalign
    # vulnerabilities with dependencies. Returns a tuple of the per-dep
    # vuln-id map and a list of `{query_index, page_token}` follow-ups for
    # any result that paginated. Tagging by index (instead of by Dependency)
    # matters because the same dep may appear in `query_deps` more than once
    # — once per query variant — and only the paginating one should be
    # re-issued.
    private def merge_batch_response(body : String, query_deps : Array(Dependency), vuln_ids_by_dep : Hash(String, Array(String))) : Array({Int32, String})
      followups = [] of {Int32, String}
      data = JSON.parse(body)

      results = dig_a(data, "results") || return followups

      if results.size != query_deps.size
        raise OsvResponseError.new(
          "OSV querybatch returned #{results.size} results for #{query_deps.size} queries; refusing to map results to dependencies"
        )
      end

      results.each_with_index do |entry, idx|
        dep = query_deps[idx]
        collect_vuln_ids(dig_a(entry, "vulns"), dep, vuln_ids_by_dep)

        if token = dig_s(entry, "next_page_token").presence
          followups << {idx, token}
        end
      end

      followups
    end

    # Merge a follow-up `/v1/query` response (single-query, possibly paged)
    # into the existing per-dep vuln-id map. Returns the next page token if
    # the follow-up itself paginated.
    private def merge_query_response(body : String, dep : Dependency, vuln_ids_by_dep : Hash(String, Array(String))) : String?
      data = JSON.parse(body)
      collect_vuln_ids(dig_a(data, "vulns"), dep, vuln_ids_by_dep)
      dig_s(data, "next_page_token").presence
    end

    private def collect_vuln_ids(vulns : Array(JSON::Any)?, dep : Dependency, vuln_ids_by_dep : Hash(String, Array(String))) : Nil
      return unless vulns
      ids = vuln_ids_by_dep[dep.name]
      vulns.each do |vuln|
        if id = dig_s(vuln, "id")
          ids << id unless ids.includes?(id)
        end
      end
    end

    private def parse_vulnerability(body : String) : Vulnerability?
      data = JSON.parse(body)

      id = dig_s(data, "id") || return
      summary = dig_s(data, "summary") || dig_s(data, "details") || ""
      aliases = dig_a(data, "aliases").try(&.compact_map(&.as_s?)) || [] of String

      severity, cvss_score = extract_severity(data)
      fixed_version, all_semver_ranges = extract_affected_ranges(data)
      url = extract_advisory_url(data, id)

      Vulnerability.new(
        id: id,
        aliases: aliases,
        summary: summary,
        severity: severity,
        cvss_score: cvss_score,
        fixed_version: fixed_version,
        url: url,
        affected_ranges: all_semver_ranges,
      )
    end

    private def extract_severity(data : JSON::Any) : {Severity, Float64?}
      severity = Severity::Unknown
      cvss_score = nil

      # Prefer the newest CVSS version we can score exactly. Entries are not
      # ordered by version, so scan for the best available rather than
      # taking the first that happens to parse.
      if severity_arr = dig_a(data, "severity")
        best_rank = -1
        severity_arr.each do |sev|
          score_str = dig_s(sev, "score") || next
          parsed = parse_cvss_score(score_str) || next
          score, rank = parsed
          next unless rank > best_rank
          best_rank = rank
          cvss_score = score
          severity = Severity.from_cvss(score)
        end
      end

      # Fallback to database_specific severity
      if severity.unknown?
        if db_severity = dig_s(data, "database_specific", "severity")
          severity = Severity.from_string(db_severity)
        end
      end

      {severity, cvss_score}
    end

    private def extract_affected_ranges(data : JSON::Any) : {String?, Array(SemverRange)}
      fixed_version = nil
      all_semver_ranges = [] of SemverRange
      # True once we meet an `affected[]` entry we cannot evaluate locally.
      unfilterable = false

      affected_arr = dig_a(data, "affected") || return {fixed_version, all_semver_ranges}

      affected_arr.each do |affected|
        ranges = dig_a(affected, "ranges") || next

        # A GIT range's events hold commit hashes. Parsing them as SemVer
        # yields nil bounds, and a nil-bounded range matches *every*
        # version — so version filtering silently became a no-op and the
        # reported fix was a commit SHA ("upgrade to >= 8b1a9953...").
        version_ranges = ranges.select { |range| version_range?(range) }

        if version_ranges.empty?
          # This entry is commit-addressed only. We query OSV with
          # `ecosystem: "GIT"`, so this is frequently the very entry OSV
          # matched us on — and judging our version against some *other*
          # entry's ecosystem range (a Go or npm packaging of the same code,
          # whose version numbers need not line up with the shard's git
          # tags) would discard a real finding. Mark it unevaluable instead.
          unfilterable = true unless ranges.empty?
          next
        end

        version_ranges.each do |range|
          events = dig_a(range, "events") || next
          fixed_version ||= first_fixed_version(events)
          all_semver_ranges.concat(SemverRangeParser.parse_osv_events(events))
        end
      end

      # Empty ranges make `Vulnerability#affected?` answer true, which is the
      # conservative result we want when part of the advisory was opaque.
      return {fixed_version, [] of SemverRange} if unfilterable

      {fixed_version, all_semver_ranges}
    end

    private def version_range?(range : JSON::Any) : Bool
      # Absent type defaults to SEMVER per the OSV schema.
      type = dig_s(range, "type") || "SEMVER"
      VERSION_RANGE_TYPES.includes?(type.upcase)
    end

    # The first `fixed` value in a version-typed range.
    #
    # Deliberately does *not* require the value to parse as SemVer. Excluding
    # GIT ranges already keeps commit hashes out; the remaining values are
    # genuine remediation guidance even when they are not strict SemVer
    # (`1.2.3.4`, `2.0.0.RELEASE`, `0:1.2.3-1.el8`). Dropping them reported
    # "no fix available" for advisories that named one.
    private def first_fixed_version(events : Array(JSON::Any)) : String?
      events.each do |event|
        if fixed = dig_s(event, "fixed").presence
          return fixed
        end
      end
      nil
    end

    private def extract_advisory_url(data : JSON::Any, id : String) : String?
      if refs = dig_a(data, "references")
        refs.each do |ref|
          ref_type = dig_s(ref, "type")
          ref_url = dig_s(ref, "url")
          next unless ref_url && (ref_type == "ADVISORY" || ref_type == "WEB")
          # Vulnerability rejects non-https URLs; skip them here so a plain
          # http reference does not shadow the canonical OSV fallback and
          # leave the finding with no URL at all.
          return ref_url if ref_url.starts_with?("https://")
        end
      end

      "https://osv.dev/vulnerability/#{id}"
    end
  end
end
