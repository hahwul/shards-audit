module Shards::Audit
  struct Dependency
    GITHUB_URL_PATTERN = /github\.com[\/:]([^\/]+)\/([^\/\.]+)/

    getter name : String
    getter git_url : String
    getter version : String?
    getter commit : String?

    def initialize(@name, @git_url, @version = nil, @commit = nil)
    end

    def github_owner_repo : String?
      if match = GITHUB_URL_PATTERN.match(git_url)
        "#{match[1]}/#{match[2]}"
      end
    end

    def github? : Bool
      !github_owner_repo.nil?
    end

    def to_s(io : IO)
      io << name
      io << " (" << version << ")" if version
      if c = commit
        io << " [" << c[0..6] << "]"
      end
    end
  end
end
