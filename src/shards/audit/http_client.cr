require "http/client"

module Shards::Audit
  module HttpClient
    private def http_request(
      base_url : String,
      method : String,
      path : String,
      headers : HTTP::Headers,
      body : String? = nil
    ) : HTTP::Client::Response
      client = get_http_client(base_url)

      case method
      when "POST"
        client.post(path, headers: headers, body: body)
      else
        client.get(path, headers: headers)
      end
    rescue ex : IO::Error | Socket::ConnectError
      # Connection may be stale — discard cached client and re-raise for retry
      @http_clients.try(&.delete(base_url))
      raise ex
    end

    private def get_http_client(base_url : String) : HTTP::Client
      @http_clients ||= Hash(String, HTTP::Client).new
      @http_clients.not_nil!.fetch(base_url) do
        uri = URI.parse(base_url)
        client = HTTP::Client.new(uri)
        client.connect_timeout = @timeout.seconds
        client.read_timeout = @timeout.seconds
        @http_clients.not_nil![base_url] = client
        client
      end
    end

    private def close_http_clients
      @http_clients.try(&.each_value(&.close))
      @http_clients.try(&.clear)
    end
  end
end
