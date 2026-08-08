require "json"

module Shards::Audit
  module OsvQueryBuilder
    private def build_commit_query(commit : String) : String
      JSON.build do |json|
        json.object do
          json.field "commit", commit
        end
      end
    end

    private def build_version_query(package_url : String, version : String) : String
      JSON.build do |json|
        json.object do
          json.field "package" do
            json.object do
              json.field "name", package_url
              json.field "ecosystem", "GIT"
            end
          end
          json.field "version", version
        end
      end
    end

    private def normalize_git_url(url : String) : String
      normalized = url.strip
      normalized = normalized.chomp(".git")
      normalized = normalized.sub(/\Agit:\/\//, "https://")
      normalized = normalized.sub(/\Agit@([^:]+):/, "https://\\1/")
      if normalized.starts_with?("https://") || normalized.starts_with?("http://")
        uri = URI.parse(normalized)
        if host = uri.host
          normalized = normalized.sub("://#{host}", "://#{host.downcase}")
        end
      end
      normalized
    rescue URI::Error
      # A malformed remote must not abort the whole batch; fall back to the
      # untouched string and let OSV simply not match it.
      url.strip
    end
  end
end
