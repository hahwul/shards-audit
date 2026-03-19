require "json"

module Shards::Audit
  module OsvQueryBuilder
    private def build_osv_query(dep : Dependency, package_url : String) : String?
      JSON.build do |json|
        json.object do
          if commit = dep.commit
            json.field "commit", commit
          elsif version = dep.version
            json.field "package" do
              json.object do
                json.field "name", package_url
                json.field "ecosystem", "GIT"
              end
            end
            json.field "version", version
          else
            # No commit or version available — skip this query
            return nil
          end
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
    end
  end
end
