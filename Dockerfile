# STAGE: Build
FROM rust:1.67.1 as builder
WORKDIR /usr/src/app

# Install cargo-strip (with layer cacheing)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
  cargo install cargo-strip

# Copy source files
COPY ./ ./

# Download dependencies and compile (with layer cacheing)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/app/target \
    cargo build --release && \
    cargo strip && \
    mv /usr/src/app/target/release/simple-forward-auth /usr/src/app

# STAGE: Minify
FROM node:19.8.1 as minifier
WORKDIR /app

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
FROM debian:buster-slim
WORKDIR /app

# Copy binary from build stage
COPY --from=builder /usr/src/app/simple-forward-auth /app/simple-forward-auth

# Copy files and assets to serve (overwritable via docker volume mount)
COPY ./public /app/public
COPY --from=minifier /app/style.css /app/public/style.css
COPY --from=minifier /app/script.js /app/public/script.js
COPY --from=minifier /app/index.html /app/public/index.html

# Set entrypoint for image
ENTRYPOINT ["./simple-forward-auth"]
