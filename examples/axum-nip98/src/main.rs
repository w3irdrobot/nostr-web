use axum::{response::IntoResponse, routing::get, Json, Router};
use nostr_web::nip98::Nip98PubKey;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // build our application with a route
    let app = Router::new().route("/", get(handler));

    // run it
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handler(Nip98PubKey(pubkey): Nip98PubKey) -> impl IntoResponse {
    Json(pubkey)
}
