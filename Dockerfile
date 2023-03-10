FROM rust:1.67.1 as builder

WORKDIR /usr/src/app
COPY . .
# RUN cargo install --path .
RUN cargo build --release

FROM debian:buster-slim

COPY --from=builder /usr/src/app/target/release/simple-forward-auth /usr/local/bin/app
CMD ["simple-forward-auth"]
