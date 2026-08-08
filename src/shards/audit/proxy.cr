require "uri"
require "socket"
require "openssl"
require "base64"

module Shards::Audit
  # Outbound HTTP(S) proxy support.
  #
  # Crystal's `HTTP::Client` has no proxy handling at all, yet the "all
  # sources failed" hint told users to "ensure HTTP_PROXY/HTTPS_PROXY are
  # set" — advice that could never have worked. On a locked-down CI runner
  # or corporate network, which is exactly where a dependency auditor is
  # meant to run, every request failed and the tool blamed the user's
  # configuration for a feature it did not have.
  module Proxy
    # Resolves the proxy for a target URI from the conventional environment
    # variables, honouring NO_PROXY exclusions.
    #
    # Lowercase names win over uppercase: `HTTP_PROXY` is also settable by a
    # `Proxy:` request header under CGI, so the lowercase form is the one
    # tools conventionally trust first.
    def self.for(target : URI, env = ENV) : URI?
      scheme = target.scheme.try(&.downcase)
      names = case scheme
              when "https" then {"https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"}
              else              {"http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"}
              end

      raw = names.each do |name|
        value = env[name]?
        break value if value && !value.empty?
      end
      return unless raw.is_a?(String)

      return if bypass?(target, env)

      parse_proxy_uri(raw)
    end

    # Schemes we can actually tunnel through. Anything else must be ignored
    # rather than attempted.
    #
    # `ALL_PROXY=socks5://…` is the standard way to configure SOCKS and is
    # commonly exported globally. We only speak HTTP CONNECT, so treating a
    # SOCKS URL as an HTTP proxy does not fail fast — it hangs until the
    # read timeout, and `IO::TimeoutError` is retryable, so every dependency
    # burned four full timeouts (two minutes at the default) before giving
    # up. Ignoring the variable falls back to a direct connection, which is
    # what happened before proxy support existed.
    SUPPORTED_SCHEMES = {"http", "https"}

    # Accepts "host:port" as well as a full URL, since both forms appear in
    # the wild.
    def self.parse_proxy_uri(raw : String) : URI?
      value = raw.strip
      return if value.empty?
      value = "http://#{value}" unless value.includes?("://")

      uri = URI.parse(value)
      return unless uri.host.presence
      return unless SUPPORTED_SCHEMES.includes?(uri.scheme.try(&.downcase))
      uri
    rescue URI::Error
      nil
    end

    def self.bypass?(target : URI, env = ENV) : Bool
      raw = env["no_proxy"]?.presence || env["NO_PROXY"]?.presence
      return false unless raw

      host = target.host.try { |h| unbracket(h.downcase) }
      return false unless host
      port = effective_port(target)

      raw.split(',').each do |entry|
        rule = entry.strip.downcase
        next if rule.empty?
        # "*" disables proxying entirely.
        return true if rule == "*"

        rule_host, rule_port = split_rule(rule)
        next if !rule_port.empty? && rule_port.to_i? != port

        rule_host = unbracket(rule_host.lchop('*'))
        if rule_host.starts_with?('.')
          return true if host.ends_with?(rule_host) || host == rule_host.lchop('.')
        elsif host == rule_host || host.ends_with?(".#{rule_host}")
          return true
        end
      end

      false
    end

    # Splits a NO_PROXY entry into host and optional port.
    #
    # An unbracketed IPv6 literal (`::1`, which curl and Go's httpproxy both
    # accept) is full of colons, so a naive "last colon is the port" rule
    # tore `::1` into host `:` port `1` and then rejected it on the port
    # comparison — traffic silently went through the proxy. Only treat a
    # trailing `:digits` as a port when what precedes it is not itself an
    # unbracketed IPv6 address.
    private def self.split_rule(rule : String) : {String, String}
      host, sep, port = rule.rpartition(':')
      return {rule, ""} if sep.empty? || host.empty?
      return {rule, ""} unless port.to_i?
      # More than one colon left over means the head is an IPv6 literal,
      # unless it is bracketed.
      return {rule, ""} if host.includes?(':') && !host.ends_with?(']')
      {host, port}
    end

    private def self.unbracket(host : String) : String
      if host.starts_with?('[') && host.ends_with?(']')
        host[1..-2]
      else
        host
      end
    end

    # The port to actually connect to: an explicit one wins over the
    # scheme default. Collapsing these two lost any non-default port, so a
    # CONNECT tunnel to `host:8443` was requested for `host:443`.
    def self.effective_port(uri : URI) : Int32
      uri.port || scheme_default_port(uri)
    end

    def self.scheme_default_port(uri : URI) : Int32
      uri.scheme.try(&.downcase) == "https" ? 443 : 80
    end

    # The CONNECT request line and headers for tunnelling to `target`.
    def self.connect_request(target_host : String, target_port : Int32, proxy : URI) : String
      authority = "#{target_host}:#{target_port}"
      String.build do |io|
        io << "CONNECT " << authority << " HTTP/1.1\r\n"
        io << "Host: " << authority << "\r\n"
        io << "User-Agent: shards-audit/" << VERSION << "\r\n"
        if header = authorization_header(proxy)
          io << "Proxy-Authorization: " << header << "\r\n"
        end
        io << "Proxy-Connection: keep-alive\r\n"
        io << "\r\n"
      end
    end

    def self.authorization_header(proxy : URI) : String?
      user = proxy.user
      return unless user
      # Credentials arrive percent-encoded in a URL userinfo section.
      credentials = "#{URI.decode(user)}:#{URI.decode(proxy.password || "")}"
      "Basic #{Base64.strict_encode(credentials)}"
    end

    # Reads and validates the proxy's CONNECT reply, consuming through the
    # blank line that terminates its headers so the caller is left with a
    # clean tunnel.
    def self.read_connect_response(io : IO) : Nil
      status_line = io.gets(chomp: true)
      raise IO::Error.new("Proxy closed the connection during CONNECT") unless status_line

      code = status_line.split(' ')[1]?.try(&.to_i?)
      unless code == 200
        raise IO::Error.new("Proxy refused CONNECT: #{status_line}")
      end

      # Drain the remaining response headers.
      while line = io.gets(chomp: true)
        break if line.empty?
      end
    end
  end
end
