module Shards::Audit
  enum OutputFormat
    Table
    Json
    Yaml
    Toml
    Sarif
  end

  class Config
    property lockfile_path : String
    property format : OutputFormat
    property github_token : String?
    property verbose : Bool
    property no_color : Bool
    property timeout : Int32
    property cache_dir : String
    property cache_ttl : Int32
    property no_cache : Bool
    property ignore_ids : Array(String)
    property severity_threshold : Severity?
    property exit_zero : Bool

    def initialize(
      @lockfile_path = "./shard.lock",
      @format = OutputFormat::Table,
      # `.presence`, because `GITHUB_TOKEN: ${{ secrets.MISSING }}` exports
      # the variable as an empty string. That is "no token", but it was read
      # as one — every request went out as `Authorization: Bearer `, GitHub
      # answered 401, and the whole GitHub source failed for a run that would
      # have worked unauthenticated.
      @github_token = ENV["GITHUB_TOKEN"]?.presence,
      @verbose = false,
      @no_color = Config.color_disabled_by_environment?,
      @timeout = 30,
      @cache_dir = Config.default_cache_dir,
      @cache_ttl = 86400,
      @no_cache = false,
      @ignore_ids = [] of String,
      @severity_threshold = nil,
      @exit_zero = false,
    )
    end

    # `--no-color` was the only way to suppress ANSI codes, so piping the
    # table output to a file or a CI log captured escape sequences. Honour
    # the two conventions that callers actually rely on: the NO_COLOR
    # standard, and stdout not being a terminal.
    def self.color_disabled_by_environment? : Bool
      return true if ENV["NO_COLOR"]?.presence
      !STDOUT.tty?
    end

    # Respects the XDG base directory spec, which is where a Linux CI image
    # or a sandboxed runner expects a cache to live.
    def self.default_cache_dir : String
      if xdg = ENV["XDG_CACHE_HOME"]?.presence
        File.join(xdg, "shards-audit")
      else
        File.join(Path.home.to_s, ".cache", "shards-audit")
      end
    end
  end

  class AuditResult
    property dependencies_scanned : Int32
    property vulnerabilities_found : Int32
    property vulnerabilities : Array(Vulnerability)
    property errors : Array(String)
    property ignored_count : Int32
    property filtered_count : Int32
    property version_filtered_count : Int32

    def initialize
      @dependencies_scanned = 0
      @vulnerabilities_found = 0
      @vulnerabilities = [] of Vulnerability
      @errors = [] of String
      @ignored_count = 0
      @filtered_count = 0
      @version_filtered_count = 0
    end

    def clean?
      vulnerabilities.empty?
    end
  end
end
