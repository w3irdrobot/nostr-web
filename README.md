# nostr-web

Utilities for building web servers for nostr

## Available utils

### NIP-98 - HTTP Auth

There are extractors for actix and axum to provide a handler with the `XOnlyPublicKey` of the event in the auth header. If the event doesn't pass the checks defined in NIP-98, then a 401 will be returned as a response instead. An example handler for axum might look like this:

```rust
use nostr_web::nip98::Nip98PubKey;

async fn handler(Nip98PubKey(pubkey): Nip98PubKey) -> impl IntoResponse {
    StatusCode::OK
}
```

## Installation

```shell
cargo add nostr-web
```

By default this will enable the parts of the code specific for [axum](https://github.com/tokio-rs/axum). However, if you'd like to use [actix-web](https://github.com/actix/actix-web) instead, use the `actix` feature instead.

```shell
cargo add nostr-web --no-default-features
```
