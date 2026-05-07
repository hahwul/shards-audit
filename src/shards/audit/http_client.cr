require "http/client"

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
      client = HTTP::Client.new(uri)
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
  end
end
