FROM rust:1.93-alpine AS build
RUN apk add --no-cache musl-dev make perl
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p mortise-accounts --features postgres,vendored-tls

FROM scratch AS artifact
COPY --from=build /build/target/release/mortise-accounts /mortise-accounts
COPY --from=build /etc/ssl/cert.pem /ca-certificates.crt
