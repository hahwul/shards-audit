module Shards::Audit
  module AdvisorySource
    abstract def scan(dependencies : Array(Dependency)) : Array(Vulnerability)
  end
end
