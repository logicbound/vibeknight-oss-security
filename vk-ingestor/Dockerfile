# ── Builder ───────────────────────────────────────────────────────────────────
FROM rust:1.85-slim AS builder

WORKDIR /build

COPY . .

RUN cargo build --release -p vk-ingestor

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/vk-ingestor /usr/local/bin/vk-ingestor

# State file lives on a named volume mounted at /data
VOLUME ["/data"]

ENTRYPOINT ["vk-ingestor", "--state", "/data/ingestor-state.json"]
