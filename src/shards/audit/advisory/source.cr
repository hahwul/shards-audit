module Shards::Audit
  module AdvisorySource
    abstract def scan(dependencies : Array(Dependency)) : Array(Vulnerability)
  end

  # A request that failed for a reason retrying cannot fix: bad credentials,
  # an exhausted rate limit, a rejected query.
  #
  # Deliberately *not* an IO::Error, which is what `HttpRetry#with_retry`
  # catches. Signalling these as IO::Error meant a rate-limited run retried
  # every dependency three times with exponential backoff — adding seconds
  # per dependency and spending four requests where one already told us the
  # quota was gone.
  class AdvisoryRequestError < Exception
  end
end
