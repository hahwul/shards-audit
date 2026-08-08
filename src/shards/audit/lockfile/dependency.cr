module Shards::Audit
  struct Dependency
    # Matches the owner/repo pair of a GitHub remote in either HTTPS
    # (`https://github.com/owner/repo.git`) or SCP-like SSH
    # (`git@github.com:owner/repo.git`) form.
    #
    # The repo segment must allow dots: the dominant Crystal naming
    # convention suffixes shards with `.cr` (`hahwul/sarif.cr`,
    # `crystal-ameba/ameba`), and an earlier `[^\/\.]+` pattern truncated
    # those to `hahwul/sarif`. That silently addressed the wrong repository
    # for every `.cr` shard — both in the GitHub advisory query and in the
    # OSV GitHub package URL — so advisories were never matched.
    #
    # A trailing `.git` and any trailing slash are stripped, and the match
    # is anchored to a path boundary so a longer URL cannot bleed extra
    # segments into the repo name.
    # The character class is restricted to what GitHub actually permits in
    # an owner or repository name (alphanumerics, hyphen, underscore, dot).
    # A permissive `[^\/\s]+` let a lockfile-controlled `git:` URL smuggle
    # `&`, `?`, or a NUL byte into the value, which is interpolated straight
    # into the advisory request path — so
    # `https://github.com/owner/repo&affects=torvalds%2Flinux` produced a
    # request carrying a second `affects` parameter.
    GITHUB_URL_PATTERN = /github\.com[\/:]([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[\/?#]|\s|$)/

    getter name : String
    getter git_url : String
    getter version : String?
    getter commit : String?
    getter github_owner_repo : String?

    def initialize(@name, @git_url, @version = nil, @commit = nil)
      @github_owner_repo = extract_github_owner_repo(@git_url)
    end

    private def extract_github_owner_repo(url : String) : String?
      match = GITHUB_URL_PATTERN.match(url.strip) || return
      owner = match[1]
      repo = match[2]
      return if owner.empty? || repo.empty?
      # `.`/`..` would escape the path when interpolated into an API route.
      return if owner.in?(".", "..") || repo.in?(".", "..")
      "#{owner}/#{repo}"
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
