FROM rust:1.93-bullseye AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/build/target \
    cargo build --release --locked -p mortise-accounts-node --features vendored-tls && \
    cp target/release/libmortise_accounts_node.so /accounts.node

FROM scratch AS artifact
COPY --from=build /accounts.node /accounts.node
COPY --from=build /etc/ssl/certs/ca-certificates.crt /ca-certificates.crt
