# ── Builder ───────────────────────────────────────────────────────────────────
FROM rust:1.85-slim AS builder

WORKDIR /build

COPY . .

RUN cargo build --release -p vk-downloader

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/vk-downloader /usr/local/bin/vk-downloader

# Artifacts live on a shared volume mounted at /artifacts
VOLUME ["/artifacts"]

ENTRYPOINT ["vk-downloader", "--artifacts", "/artifacts"]
