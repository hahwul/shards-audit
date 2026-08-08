require "http/client"
require "./proxy"

module Shards::Audit
  module HttpClient
    private def http_request(
      base_url : String,
      method : String,
      path : String,
      headers : HTTP::Headers,
      body : String? = nil,
    ) : HTTP::Client::Response
      uri = URI.parse(base_url)
      client = build_client(uri)
      client.connect_timeout = @timeout.seconds
      client.read_timeout = @timeout.seconds

      begin
        case method
        when "POST"
          client.post(path, headers: headers, body: body)
        else
          client.get(path, headers: headers)
        end
      ensure
        client.close
      end
    end

    private def build_client(uri : URI) : HTTP::Client
      proxy = Proxy.for(uri)
      return HTTP::Client.new(uri) unless proxy

      tunnel = open_proxy_tunnel(uri, proxy)
      HTTP::Client.new(tunnel, uri.host.to_s, Proxy.effective_port(uri))
    end

    # Establishes a CONNECT tunnel and, for https targets, negotiates TLS
    # *inside* it. TLS must terminate at the origin rather than the proxy,
    # so the handshake runs over the tunnelled socket with the origin
    # hostname — that keeps certificate and hostname verification pointed at
    # api.osv.dev / api.github.com, not at the proxy.
    private def open_proxy_tunnel(uri : URI, proxy : URI) : IO
      host = uri.host
      raise IO::Error.new("Cannot proxy a URL without a host: #{uri}") unless host
      port = Proxy.effective_port(uri)

      socket = TCPSocket.new(
        proxy.host.to_s,
        proxy.port || Proxy.scheme_default_port(proxy),
        connect_timeout: @timeout.seconds
      )

      begin
        socket.read_timeout = @timeout.seconds
        socket.sync = true
        socket << Proxy.connect_request(host, port, proxy)
        socket.flush
        Proxy.read_connect_response(socket)

        return socket unless uri.scheme.try(&.downcase) == "https"

        context = OpenSSL::SSL::Context::Client.new
        OpenSSL::SSL::Socket::Client.new(socket, context: context, sync_close: true, hostname: host)
      rescue ex
        socket.close rescue nil
        raise ex
      end
    end
  end
end
