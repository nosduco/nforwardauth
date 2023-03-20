# STAGE: Build
FROM rust:1.68.0-alpine3.17 as builder
WORKDIR /build

# Install alpine deps
RUN apk add --no-cache build-base

# Install cargo-strip (with layer cacheing)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
  cargo install cargo-strip

# Copy source files
COPY ./ ./

# Download dependencies and compile (with layer cacheing)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release && \
    cargo strip && \
    mv /build/target/release/nforwardauth /build

# STAGE: Minify
FROM node:19.8.1 as minifier
WORKDIR /build

# Install CSS minifier (lightningcss)
RUN npm install -g lightningcss-cli

# Install JS minifier (uglify-js)
RUN npm install -g uglify-js

# Install HTML minifier (html-minifier)
RUN npm install -g html-minifier

# Copy assets folder
COPY ./assets ./assets

# Minify CSS
RUN npx lightningcss --minify --bundle --targets '>= 0.25%' ./assets/css/style.css -o ./style.css

# Minify JS
RUN npx uglifyjs --compress --mangle -o ./script.js -- ./assets/js/script.js 

# Minify HTML
RUN npx html-minifier --collapse-whitespace --remove-comments --remove-original-tags --remove-rundundant-attributes --remove-script-type-attributes --remove-tag-whitespace --use-short-doctype -o ./index.html ./assets/html/index.html

# STAGE: Release
FROM alpine:3.17

# Copy binary from build stage
COPY --from=builder /build/nforwardauth /nforwardauth

# Copy files and assets to serve (overwritable via docker volume mount)
COPY ./public /public
COPY --from=minifier /build/style.css /public/style.css
COPY --from=minifier /build/script.js /public/script.js
COPY --from=minifier /build/index.html /public/index.html

# Set entrypoint for image
ENTRYPOINT ["/nforwardauth"]
