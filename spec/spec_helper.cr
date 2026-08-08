require "spec"
require "../src/shards-audit"

FIXTURES_PATH = File.join(__DIR__, "fixtures")

# Diagnostics now share one sink (CLI.stderr delegates to
# Shards::Audit.stderr), so anything a spec triggers would otherwise print
# over the runner's output. Park it in memory by default; specs that assert
# on stderr swap in their own buffer and restore this one.
SPEC_STDERR = IO::Memory.new
Shards::Audit.stderr = SPEC_STDERR
