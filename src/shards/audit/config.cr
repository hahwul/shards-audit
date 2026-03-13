module Shards::Audit
  enum OutputFormat
    Table
    Json
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

    def initialize(
      @lockfile_path = "./shard.lock",
      @format = OutputFormat::Table,
      @github_token = ENV["GITHUB_TOKEN"]?,
      @verbose = false,
      @no_color = false,
      @timeout = 30,
      @cache_dir = File.join(Path.home.to_s, ".cache", "shards-audit"),
      @cache_ttl = 86400,
      @no_cache = false,
      @ignore_ids = [] of String,
      @severity_threshold = nil
    )
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
