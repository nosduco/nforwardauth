# Build stage
FROM rust:1.67.1 as builder
WORKDIR /usr/src/app

# Install cargo-strip (with layer cacheing)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
  cargo install cargo-strip

# Copy source files
COPY . .

# Download dependencies and compile (with layer cacheing)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/app/target \
    cargo build --release && \
    cargo strip && \
    mv /usr/src/app/target/release/simple-forward-auth /usr/src/app

# Release stage
FROM debian:buster-slim
WORKDIR /app

# Copy binary from build stage
COPY --from=builder /usr/src/app/simple-forward-auth /app/simple-forward-auth

# Copy files to serve (overwritable via docker volume mount)
COPY ./public /app/public

# Set entrypoint for image
ENTRYPOINT ["./simple-forward-auth"]
