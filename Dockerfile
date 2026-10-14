##= BUILDER =##
# Static musl build, same as release-binary.yml. The glibc image (Ubuntu 26.04
# since 1.22) can't link OpenSSL statically without libjitterentropy.a.
FROM crystallang/crystal:1.22.0-alpine AS builder
WORKDIR /app
COPY . .

RUN apk add --no-cache yaml-dev yaml-static zlib-dev zlib-static zstd-dev zstd-static git && \
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

# OSV/GitHub lookups are HTTPS; debian-slim ships no CA bundle.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/bin/shards-audit /usr/local/bin/shards-audit

WORKDIR /src
ENTRYPOINT ["shards-audit"]
