##= BUILDER =##
FROM crystallang/crystal:1.20.0 AS builder
WORKDIR /app
COPY . .

RUN apt-get update && \
    apt-get install -y --no-install-recommends libyaml-dev libzstd-dev zlib1g-dev pkg-config && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    mv /usr/bin/pkg-config /usr/bin/pkg-config-original && \
    echo '#!/bin/sh' > /usr/bin/pkg-config && \
    echo 'if echo "$@" | grep -q -- "--libs"; then' >> /usr/bin/pkg-config && \
    echo '  exec /usr/bin/pkg-config-original "$@" --static' >> /usr/bin/pkg-config && \
    echo 'else' >> /usr/bin/pkg-config && \
    echo '  exec /usr/bin/pkg-config-original "$@"' >> /usr/bin/pkg-config && \
    echo 'fi' >> /usr/bin/pkg-config && \
    chmod +x /usr/bin/pkg-config && \
    shards install --production && \
    shards build --release --no-debug --production --static

##= RUNNER =##
FROM debian:13-slim
LABEL org.opencontainers.image.title="shards-audit"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.description="Security vulnerability scanner for Crystal shard dependencies"
LABEL org.opencontainers.image.authors="hahwul <hahwul@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/hahwul/shards-audit"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=builder /app/bin/shards-audit /usr/local/bin/shards-audit

WORKDIR /src
ENTRYPOINT ["shards-audit"]
