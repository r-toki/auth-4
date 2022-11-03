#!/usr/bin/env bash
cargo build --release
cargo install sqlx-cli --no-default-features --features rustls,mysql
sqlx database create
sqlx migrate run
