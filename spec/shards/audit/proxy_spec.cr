require "../../spec_helper"

private def proxy_for(url : String, env : Hash(String, String))
  Shards::Audit::Proxy.for(URI.parse(url), env)
end

describe Shards::Audit::Proxy do
  describe ".for" do
    it "resolves HTTPS_PROXY for an https target" do
      proxy_for("https://api.osv.dev", {"HTTPS_PROXY" => "http://proxy.local:3128"})
        .try(&.to_s).should eq("http://proxy.local:3128")
    end

    it "resolves HTTP_PROXY for an http target" do
      proxy_for("http://example.com", {"HTTP_PROXY" => "http://proxy.local:3128"})
        .try(&.to_s).should eq("http://proxy.local:3128")
    end

    it "does not use HTTP_PROXY for an https target" do
      proxy_for("https://api.osv.dev", {"HTTP_PROXY" => "http://proxy.local:3128"}).should be_nil
    end

    it "falls back to ALL_PROXY" do
      proxy_for("https://api.osv.dev", {"ALL_PROXY" => "http://proxy.local:3128"})
        .try(&.host).should eq("proxy.local")
    end

    it "prefers the lowercase variable" do
      env = {"https_proxy" => "http://lower:1", "HTTPS_PROXY" => "http://upper:2"}
      proxy_for("https://api.osv.dev", env).try(&.host).should eq("lower")
    end

    it "accepts a bare host:port" do
      uri = proxy_for("https://api.osv.dev", {"HTTPS_PROXY" => "proxy.local:3128"}).not_nil!
      uri.scheme.should eq("http")
      uri.host.should eq("proxy.local")
      uri.port.should eq(3128)
    end

    it "ignores an empty value" do
      proxy_for("https://api.osv.dev", {"HTTPS_PROXY" => ""}).should be_nil
    end

    it "ignores a malformed value rather than raising" do
      proxy_for("https://api.osv.dev", {"HTTPS_PROXY" => "http://"}).should be_nil
    end

    it "returns nil when nothing is configured" do
      proxy_for("https://api.osv.dev", {} of String => String).should be_nil
    end
  end

  describe "NO_PROXY handling" do
    it "bypasses an exact host match" do
      proxy_for("https://api.osv.dev", {"HTTPS_PROXY" => "p:1", "NO_PROXY" => "api.osv.dev"}).should be_nil
    end

    it "bypasses a leading-dot suffix match" do
      proxy_for("https://api.github.com", {"HTTPS_PROXY" => "p:1", "NO_PROXY" => ".github.com"}).should be_nil
    end

    it "bypasses a bare-domain suffix match" do
      proxy_for("https://api.github.com", {"HTTPS_PROXY" => "p:1", "NO_PROXY" => "github.com"}).should be_nil
    end

    it "bypasses everything for '*'" do
      proxy_for("https://api.osv.dev", {"HTTPS_PROXY" => "p:1", "NO_PROXY" => "*"}).should be_nil
    end

    it "does not bypass an unrelated host" do
      proxy_for("https://api.osv.dev", {"HTTPS_PROXY" => "http://p:1", "NO_PROXY" => "example.com"})
        .should_not be_nil
    end

    it "does not treat a suffix-only string match as a domain match" do
      # "osv.dev" must not match "notosv.dev"
      proxy_for("https://notosv.dev", {"HTTPS_PROXY" => "http://p:1", "NO_PROXY" => "osv.dev"})
        .should_not be_nil
    end

    it "honours a port qualifier" do
      env = {"HTTPS_PROXY" => "http://p:1", "NO_PROXY" => "api.osv.dev:8443"}
      proxy_for("https://api.osv.dev", env).should_not be_nil
      proxy_for("https://api.osv.dev:8443", env).should be_nil
    end

    it "handles whitespace and empty entries" do
      env = {"HTTPS_PROXY" => "p:1", "NO_PROXY" => " , api.osv.dev , "}
      proxy_for("https://api.osv.dev", env).should be_nil
    end
  end

  describe ".connect_request" do
    it "builds an absolute-authority CONNECT request" do
      req = Shards::Audit::Proxy.connect_request("api.osv.dev", 443, URI.parse("http://proxy:3128"))
      req.lines.first.should eq("CONNECT api.osv.dev:443 HTTP/1.1")
      req.should contain("Host: api.osv.dev:443")
      req.should end_with("\r\n\r\n")
      req.should_not contain("Proxy-Authorization")
    end

    it "includes basic credentials when the proxy URL carries them" do
      req = Shards::Audit::Proxy.connect_request("api.osv.dev", 443, URI.parse("http://user:pass@proxy:3128"))
      req.should contain("Proxy-Authorization: Basic #{Base64.strict_encode("user:pass")}")
    end

    it "percent-decodes credentials" do
      req = Shards::Audit::Proxy.connect_request("h", 443, URI.parse("http://u%40b:p%20w@proxy:3128"))
      req.should contain("Proxy-Authorization: Basic #{Base64.strict_encode("u@b:p w")}")
    end
  end

  describe ".read_connect_response" do
    it "accepts a 200 reply and consumes its headers" do
      io = IO::Memory.new("HTTP/1.1 200 Connection established\r\nX-Proxy: yes\r\n\r\nPAYLOAD")
      Shards::Audit::Proxy.read_connect_response(io)
      io.gets_to_end.should eq("PAYLOAD")
    end

    it "raises on a refusal" do
      io = IO::Memory.new("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
      expect_raises(IO::Error, /407/) do
        Shards::Audit::Proxy.read_connect_response(io)
      end
    end

    it "raises when the proxy hangs up" do
      expect_raises(IO::Error, /closed/) do
        Shards::Audit::Proxy.read_connect_response(IO::Memory.new(""))
      end
    end
  end
end

describe "HTTP requests through a proxy" do
  # Exercises the real CONNECT path end to end: a fake proxy tunnels to a
  # local origin server and the client must speak CONNECT to reach it.
  it "tunnels a request through a CONNECT proxy" do
    origin = TCPServer.new("127.0.0.1", 0)
    origin_port = origin.local_address.port
    spawn do
      while sock = origin.accept?
        spawn do
          while line = sock.gets(chomp: true)
            break if line.empty?
          end
          body = %({"ok":true})
          sock << "HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\n\r\n#{body}"
          sock.flush
          sock.close
        end
      end
    end

    connect_seen = Channel(String).new(1)
    proxy_server = TCPServer.new("127.0.0.1", 0)
    proxy_port = proxy_server.local_address.port
    spawn do
      while client = proxy_server.accept?
        spawn do
          request_line = client.gets(chomp: true).to_s
          connect_seen.send(request_line)
          while line = client.gets(chomp: true)
            break if line.empty?
          end
          upstream = TCPSocket.new("127.0.0.1", origin_port)
          client << "HTTP/1.1 200 Connection established\r\n\r\n"
          client.flush
          spawn { IO.copy(client, upstream) rescue nil }
          IO.copy(upstream, client) rescue nil
        end
      end
    end

    probe = ProxyHttpProbe.new
    ENV["HTTP_PROXY"] = "http://127.0.0.1:#{proxy_port}"
    begin
      response = probe.get("http://127.0.0.1:#{origin_port}", "/v1/query")
      response.status_code.should eq(200)
      response.body.should eq(%({"ok":true}))
      connect_seen.receive.should eq("CONNECT 127.0.0.1:#{origin_port} HTTP/1.1")
    ensure
      ENV.delete("HTTP_PROXY")
      proxy_server.close
      origin.close
    end
  end

  it "connects directly when NO_PROXY excludes the host" do
    origin = TCPServer.new("127.0.0.1", 0)
    origin_port = origin.local_address.port
    spawn do
      while sock = origin.accept?
        spawn do
          while line = sock.gets(chomp: true)
            break if line.empty?
          end
          sock << "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
          sock.flush
          sock.close
        end
      end
    end

    ENV["HTTP_PROXY"] = "http://127.0.0.1:1" # would fail if actually used
    ENV["NO_PROXY"] = "127.0.0.1"
    begin
      ProxyHttpProbe.new.get("http://127.0.0.1:#{origin_port}", "/").status_code.should eq(204)
    ensure
      ENV.delete("HTTP_PROXY")
      ENV.delete("NO_PROXY")
      origin.close
    end
  end
end

private class ProxyHttpProbe
  include Shards::Audit::HttpClient

  def initialize(@timeout : Int32 = 5)
  end

  def get(base : String, path : String)
    http_request(base, "GET", path, HTTP::Headers.new)
  end
end
