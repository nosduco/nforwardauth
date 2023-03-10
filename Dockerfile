FROM rust:1.67.1 as builder

RUN USER=root cargo new --bin simple-forward-auth
WORKDIR ./simple-forward-auth


