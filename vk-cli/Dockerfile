# ── Builder ───────────────────────────────────────────────────────────────────
FROM rust:1.85-slim AS builder

WORKDIR /build

COPY . .

RUN cargo build --release -p vk-cli

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/vk /usr/local/bin/vk

# Artifacts (read) and findings (write) live on named volumes.
VOLUME ["/artifacts", "/vk-output"]

ENTRYPOINT ["vk", "daemon", "--output", "/vk-output"]
