# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM rust:1-bookworm AS build
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; compiler=gcc-x86-64-linux-gnu; cross_libc=libc6-dev-amd64-cross ;; \
      arm64) triple=aarch64-unknown-linux-gnu; compiler=gcc-aarch64-linux-gnu; cross_libc=libc6-dev-arm64-cross ;; \
      *) exit 1 ;; \
    esac && printf '%s' "$triple" > /target-triple && \
    rustup target add "$triple" && \
    if [ "$(dpkg --print-architecture)" != "$TARGETARCH" ]; then \
      dpkg --add-architecture "$TARGETARCH" && \
      apt-get update && apt-get install -y --no-install-recommends \
        "$compiler" "$cross_libc" pkg-config "libssl-dev:$TARGETARCH"; \
    else \
      apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev pkg-config libssl-dev; \
    fi && rm -rf /var/lib/apt/lists/*
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    CFLAGS_x86_64_unknown_linux_gnu=-I/usr/include/x86_64-linux-gnu \
    CFLAGS_aarch64_unknown_linux_gnu=-I/usr/include/aarch64-linux-gnu \
    PKG_CONFIG_ALLOW_CROSS=1 \
    PKG_CONFIG_LIBDIR_x86_64_unknown_linux_gnu=/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig \
    PKG_CONFIG_LIBDIR_aarch64_unknown_linux_gnu=/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor
COPY src ./src
# Retain the shared cache namespace from before the project rename.
RUN --mount=type=cache,id=codex-http-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=codex-http-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=codex-http-native-${TARGETARCH},target=/build/target \
    cargo build --release --locked --target "$(cat /target-triple)" && \
    mkdir -p /out && cp "target/$(cat /target-triple)/release/right-codex" /out/

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="right-codex" \
      org.opencontainers.image.source="https://github.com/1198722360/right-codex" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --create-home engine
COPY --from=build /out/right-codex /usr/local/bin/right-codex
COPY LICENSE NOTICE /usr/share/doc/right-codex/
COPY vendor/codex/LICENSE vendor/codex/NOTICE /usr/share/doc/right-codex/upstream/
WORKDIR /app
USER 10001:10001
EXPOSE 18184
ENTRYPOINT ["right-codex"]
CMD ["/app/config.json"]
