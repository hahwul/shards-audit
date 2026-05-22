require "file_utils"

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
      File.chmod(dir, File::Permissions.new(0o700))

      File.write(path, value)
      File.chmod(path, File::Permissions.new(0o600))
    rescue IO::Error
      # Silently ignore cache write failures
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
      # Replace non-safe characters (keep alphanumeric, /, -, ., _)
      sanitized = key.gsub(/[^\w\/\-\.]/, "_")

      # Remove path traversal components and lone dots
      parts = sanitized.split("/").reject { |p| p == ".." || p == "." || p.empty? }
      return if parts.empty?

      sanitized = parts.join("/")
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
