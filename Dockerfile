# Build stage
FROM rust:1.67.1 as builder
WORKDIR /usr/src/app

# Copy source files, download dependencies, and compile
COPY . .
RUN ["cargo", "build", "--release"]

# Release stage
FROM debian:buster-slim
WORKDIR /app

# Copy binary
COPY --from=builder /usr/src/app/target/release/simple-forward-auth /app/simple-forward-auth

# Copy files to serve (overwritable via docker volume mount)
COPY ./public /app/public

# Set entrypoint for image
ENTRYPOINT ["./simple-forward-auth"]
