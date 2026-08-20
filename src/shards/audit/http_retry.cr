require "http"

module Shards::Audit
  # A retryable HTTP status, carrying the server's own `Retry-After` advice
  # when it sent one.
  #
  # An IO::Error so `with_retry` keeps catching it, which is how retryable
  # statuses were already signalled.
  class RetryableResponseError < IO::Error
    getter retry_after : Float64?

    def initialize(message : String, @retry_after : Float64? = nil)
      super(message)
    end
  end

  module HttpRetry
    MAX_RETRY_DELAY = 30.0

    def with_retry(max_retries : Int32 = 3, base_delay : Float64 = 0.5, &)
      retries = 0
      loop do
        begin
          return yield
        rescue ex : IO::Error | Socket::ConnectError | IO::TimeoutError
          retries += 1
          raise ex if retries > max_retries
          actual_delay = retry_delay(ex, retries, base_delay)
          Shards::Audit.stderr.puts("[Retry] Attempt #{retries}/#{max_retries} after #{actual_delay.round(2)}s: #{ex.message}") if @verbose
          sleep(actual_delay.seconds)
        end
      end
    end

    # How long to wait before attempt `attempt`.
    #
    # A server that answers 429 or 503 with `Retry-After` is telling us
    # exactly when it will serve us again. Ignoring it meant retrying after
    # 0.5s against a window that had not reopened, burning the remaining two
    # attempts and failing the dependency — while the same header, honoured,
    # would have succeeded.
    def retry_delay(ex : Exception, attempt : Int32, base_delay : Float64) : Float64
      if ex.is_a?(RetryableResponseError) && (after = ex.retry_after)
        return Math.min(after, MAX_RETRY_DELAY)
      end

      delay = Math.min(base_delay * (2 ** (attempt - 1)), MAX_RETRY_DELAY)
      delay + delay * 0.1 * Random.rand
    end

    # RFC 9110 §10.2.3: `Retry-After` is either a delay in seconds or an
    # HTTP-date. A date already in the past means "retry now".
    def retry_after_seconds(value : String?) : Float64?
      raw = value.try(&.strip)
      return if raw.nil? || raw.empty?

      if seconds = raw.to_f?
        return seconds < 0 ? nil : seconds
      end

      time = HTTP.parse_time(raw) || return
      delta = (time - Time.utc).total_seconds
      delta < 0 ? 0.0 : delta
    end

    def retryable_status?(status_code : Int32) : Bool
      status_code.in?(429, 500, 502, 503, 504)
    end
  end
end
