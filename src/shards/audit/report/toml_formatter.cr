module Shards::Audit
  class TomlFormatter
    def format(result : AuditResult, io : IO = STDOUT) : Nil
      io.puts "tool_version = #{quote(VERSION)}"
      io.puts "timestamp = #{quote(Time.utc.to_rfc3339)}"
      io.puts "dependencies_scanned = #{result.dependencies_scanned}"
      io.puts "vulnerabilities_found = #{result.vulnerabilities_found}"
      io.puts "version_filtered_count = #{result.version_filtered_count}"
      io.puts "ignored_count = #{result.ignored_count}"
      io.puts "filtered_count = #{result.filtered_count}"
      io.puts "errors = [#{result.errors.map { |e| quote(e) }.join(", ")}]"

      result.vulnerabilities.each do |vuln|
        io.puts
        io.puts "[[vulnerabilities]]"
        io.puts "id = #{quote(vuln.id)}"
        io.puts "aliases = [#{vuln.aliases.map { |a| quote(a) }.join(", ")}]"
        io.puts "summary = #{quote(vuln.summary)}"
        io.puts "severity = #{quote(vuln.severity.label)}"
        if score = vuln.cvss_score
          io.puts "cvss_score = #{score}"
        end
        if fixed = vuln.fixed_version
          io.puts "fixed_version = #{quote(fixed)}"
        end
        io.puts "dependency_name = #{quote(vuln.dependency_name)}"
        io.puts "source = #{quote(vuln.source)}"
        if url = vuln.url
          io.puts "url = #{quote(url)}"
        end

        vuln.affected_ranges.each do |range|
          io.puts
          io.puts "  [[vulnerabilities.affected_ranges]]"
          if intro = range.introduced
            io.puts "  introduced = #{quote(intro.to_s)}"
          end
          if fix = range.fixed
            io.puts "  fixed = #{quote(fix.to_s)}"
          end
          io.puts "  introduced_exclusive = #{range.introduced_exclusive}"
          io.puts "  fixed_inclusive = #{range.fixed_inclusive}"
          io.puts "  constraint = #{quote(range.to_constraint)}"
        end
      end
    end

    # TOML basic strings forbid unescaped control characters (U+0000-U+0008,
    # U+000A-U+001F, U+007F). Only `\n` was handled, so an advisory summary
    # containing a carriage return — common in feeds that wrap text with
    # CRLF — emitted a document no TOML parser would accept.
    private def quote(str : String) : String
      String.build do |io|
        io << '"'
        str.each_char do |char|
          case char
          when '\\' then io << "\\\\"
          when '"'  then io << "\\\""
          when '\b' then io << "\\b"
          when '\f' then io << "\\f"
          when '\n' then io << "\\n"
          when '\r' then io << "\\r"
          when '\t' then io << "\\t"
          else
            if char.control?
              io << "\\u" << char.ord.to_s(16, upcase: true).rjust(4, '0')
            else
              io << char
            end
          end
        end
        io << '"'
      end
    end
  end
end
