require "file_utils"
require "digest/sha256"

module Shards::Audit
  class Cache
    MAX_CACHE_VALUE_SIZE = 10 * 1024 * 1024 # 10MB

    def initialize(@base_dir : String, @ttl_seconds : Int32 = 86400)
    end

    def get(key : String) : String?
      path = safe_path(key)
      return unless path

      info = File.info(path, follow_symlinks: false)
      return if info.symlink?

      mtime = info.modification_time
      if (Time.utc - mtime).total_seconds > @ttl_seconds
        File.delete(path) rescue nil
        return
      end

      File.read(path)
    rescue File::NotFoundError
      nil
    rescue IO::Error
      nil
    end

    def set(key : String, value : String) : Nil
      return if value.bytesize > MAX_CACHE_VALUE_SIZE
      path = safe_path(key)
      return unless path

      dir = File.dirname(path)
      Dir.mkdir_p(dir)

      # `get` refused to read through a symlink but `set` happily wrote
      # through one, so the protection only covered half the operation. A
      # pre-planted symlink at the cache path made us overwrite an arbitrary
      # file, and a symlinked *directory* additionally got chmod 0700
      # applied to whatever it pointed at.
      return unless within_base?(dir)
      File.chmod(dir, File::Permissions.new(0o700))

      return if symlink?(path)
      File.write(path, value)
      File.chmod(path, File::Permissions.new(0o600))
    rescue IO::Error
      # Silently ignore cache write failures
    end

    private def symlink?(path : String) : Bool
      File.info(path, follow_symlinks: false).symlink?
    rescue File::NotFoundError
      false
    rescue IO::Error
      true
    end

    # Resolves symlinks on both sides so a symlinked component anywhere in
    # the directory chain cannot land the write outside the cache.
    private def within_base?(dir : String) : Bool
      return false if symlink?(dir)
      real_base = File.realpath(@base_dir)
      real_dir = File.realpath(dir)
      real_dir == real_base || real_dir.starts_with?(real_base + File::SEPARATOR)
    rescue File::Error
      false
    end

    def clear : Nil
      return unless Dir.exists?(@base_dir)
      # Do not follow symlinks - refuse to delete if base_dir is a symlink
      if File.info(@base_dir, follow_symlinks: false).symlink?
        return
      end
      FileUtils.rm_rf(@base_dir)
    end

    private def safe_path(key : String) : String?
      return if @base_dir.empty?

      # Replace non-safe characters (keep alphanumeric, /, -, ., _)
      sanitized = key.gsub(/[^\w\/\-\.]/, "_")

      # Remove path traversal components and lone dots
      parts = sanitized.split("/").reject { |p| p == ".." || p == "." || p.empty? }
      return if parts.empty?

      sanitized = parts.join("/")

      # Sanitising is lossy, so two distinct keys can land on one file and
      # the second would be served the first one's advisory. Advisory ids
      # come from the server, so disambiguate whenever the key was altered.
      unless sanitized == key
        sanitized = "#{sanitized}-#{Digest::SHA256.hexdigest(key)[0, 12]}"
      end

      path = File.join(@base_dir, sanitized)

      # Final check: expanded path must be inside base_dir
      expanded_base = File.expand_path(@base_dir)
      expanded_path = File.expand_path(path)
      unless expanded_path.starts_with?(expanded_base)
        return
      end

      path
    end
  end
end
