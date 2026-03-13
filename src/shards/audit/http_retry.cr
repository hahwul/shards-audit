module Shards::Audit
  module HttpRetry
    MAX_RETRY_DELAY = 30.0

    def with_retry(max_retries : Int32 = 3, base_delay : Float64 = 0.5, &block)
      retries = 0
      loop do
        begin
          return yield
        rescue ex : IO::Error | Socket::ConnectError | IO::TimeoutError
          retries += 1
          raise ex if retries > max_retries
          delay = Math.min(base_delay * (2 ** (retries - 1)), MAX_RETRY_DELAY)
          jitter = delay * 0.1 * Random.rand
          actual_delay = delay + jitter
          STDERR.puts("[Retry] Attempt #{retries}/#{max_retries} after #{actual_delay.round(2)}s: #{ex.message}") if @verbose
          sleep(actual_delay.seconds)
        end
      end
    end

    def retryable_status?(status_code : Int32) : Bool
      status_code.in?(429, 500, 502, 503, 504)
    end
  end
end
