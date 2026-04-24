# ── Builder ───────────────────────────────────────────────────────────────────
FROM rust:1.85-slim AS builder

WORKDIR /build

# Copy workspace manifests first so dependency layers are cached.
COPY Cargo.toml Cargo.lock ./
COPY macros/Cargo.toml        macros/Cargo.toml
COPY vk-ir/Cargo.toml         vk-ir/Cargo.toml
COPY vk-npm/Cargo.toml        vk-npm/Cargo.toml
COPY vk-lang-js/Cargo.toml    vk-lang-js/Cargo.toml
COPY vk-core/Cargo.toml       vk-core/Cargo.toml
COPY vk-cli/Cargo.toml        vk-cli/Cargo.toml
COPY vk-ingestor/Cargo.toml   vk-ingestor/Cargo.toml
COPY vk-downloader/Cargo.toml vk-downloader/Cargo.toml

# Stub out every crate src so cargo can resolve the dep graph.
RUN find . -name Cargo.toml -not -path './Cargo.toml' | \
    while read f; do \
      dir=$(dirname "$f"); \
      mkdir -p "$dir/src"; \
      if grep -q '\[\[bin\]\]' "$f"; then \
        echo 'fn main(){}' > "$dir/src/main.rs"; \
      else \
        touch "$dir/src/lib.rs"; \
      fi; \
    done

RUN cargo build --release -p vk-ingestor 2>/dev/null || true

# Now copy real source and rebuild only what changed.
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
