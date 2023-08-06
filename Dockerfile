# STAGE: Build
FROM rust:1-alpine3.17 as builder
WORKDIR /build

# Install alpine deps
RUN apk add --no-cache build-base

# Install cargo-strip (with layer caching)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
  cargo install cargo-strip

# Copy source files
COPY ./ ./

# Download dependencies and compile (with layer caching)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release && \
    cargo strip && \
    mv /build/target/release/nforwardauth /build

# STAGE: Minify
FROM node:19.8.1 as minifier
WORKDIR /build

# Install CSS minifier (lightningcss), JS minifier (uglify-js), and HTML minifier (html-minifier)
RUN npm install -g lightningcss-cli@1.21.5 \
  && npm install -g uglify-js@3.17.4 \
  && npm install -g html-minifier@4.0.0

# Copy assets folder
COPY ./assets ./assets

# Minify CSS
RUN npx lightningcss --minify --bundle --targets '>= 0.25%' ./assets/css/style.css -o ./style.css

# Minify JS
RUN npx uglifyjs --compress --mangle -o ./script.js -- ./assets/js/script.js  \
    && npx uglifyjs --compress --mangle -o ./logout.js -- ./assets/js/logout.js 

# Minify HTML
RUN npx html-minifier --collapse-whitespace --remove-comments --remove-original-tags --remove-rundundant-attributes --remove-script-type-attributes --remove-tag-whitespace --use-short-doctype -o ./index.html ./assets/html/index.html \
  && npx html-minifier --collapse-whitespace --remove-comments --remove-original-tags --remove-rundundant-attributes --remove-script-type-attributes --remove-tag-whitespace --use-short-doctype -o ./logout.html ./assets/html/logout.html

# STAGE: Release
FROM alpine:3.17

# Copy binary from build stage
COPY --from=builder /build/nforwardauth /nforwardauth

# Copy files and assets to serve (overwritable via docker volume mount)
COPY ./public /public
COPY --from=minifier /build/style.css /public/style.css
COPY --from=minifier /build/script.js /public/script.js
COPY --from=minifier /build/logout.js /public/logout.js
COPY --from=minifier /build/index.html /public/index.html
COPY --from=minifier /build/logout.html /public/logout.html

# Set entrypoint for image
ENTRYPOINT ["/nforwardauth"]
