use base64::{engine::general_purpose::STANDARD, Engine};
use nostr::{key::XOnlyPublicKey, nips::nip98::HttpData, Event, HttpMethod, Kind};
use std::{fmt::Display, str::FromStr};
use time::OffsetDateTime;
use url::Url;

#[cfg(feature = "actix")]
use actix_web::{error, FromRequest, HttpRequest};
#[cfg(feature = "actix")]
use futures::future::{ready, Ready};

#[cfg(feature = "axum")]
use async_trait::async_trait;
#[cfg(feature = "axum")]
use axum::http::{header::AUTHORIZATION, request::Parts, StatusCode};
#[cfg(feature = "axum")]
use axum_core::extract::FromRequestParts;

const SCHEME: &str = "Nostr";

pub struct Nip98PubKey(pub XOnlyPublicKey);

impl From<XOnlyPublicKey> for Nip98PubKey {
    fn from(value: XOnlyPublicKey) -> Self {
        Self(value)
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidAuthHeader,
    InvalidScheme,
    InvalidBase64,
    InvalidEvent,
    InvalidTimestamp,
    TimestampOutOfRange,
    UrlMismatch,
    MethodMismatch,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAuthHeader => write!(f, "invalid authorization header"),
            Self::InvalidScheme => write!(f, "invalid scheme"),
            Self::InvalidBase64 => write!(f, "invalid base64 string"),
            Self::InvalidEvent => write!(f, "invalid nostr event"),
            Self::InvalidTimestamp => write!(f, "invalid timestamp"),
            Self::TimestampOutOfRange => write!(f, "timestamp out of range"),
            Self::UrlMismatch => write!(f, "url in event does not match"),
            Self::MethodMismatch => write!(f, "method in event does not match"),
        }
    }
}

#[cfg(feature = "axum")]
impl From<Error> for StatusCode {
    fn from(_value: Error) -> Self {
        StatusCode::UNAUTHORIZED
    }
}

#[cfg(feature = "actix")]
impl From<Error> for actix_web::Error {
    fn from(value: Error) -> Self {
        error::ErrorUnauthorized(value.to_string())
    }
}

pub fn validate_nip98(auth: &str, url: Url, method: &str) -> Result<Event, Error> {
    if !auth.starts_with(SCHEME) {
        return Err(Error::InvalidScheme);
    }

    let token = auth[SCHEME.len()..].trim().to_string();
    let token = STANDARD.decode(&token).map_err(|_| Error::InvalidBase64)?;
    let event = serde_json::from_slice::<Event>(&token).map_err(|_| Error::InvalidEvent)?;

    if event.kind != Kind::HttpAuth {
        return Err(Error::InvalidEvent);
    }

    let created_at = OffsetDateTime::from_unix_timestamp(event.created_at.as_i64())
        .map_err(|_| Error::InvalidTimestamp)?;
    let diff = OffsetDateTime::now_utc() - created_at;

    if diff.whole_seconds() > 10_i64 {
        return Err(Error::TimestampOutOfRange);
    }

    let http_data = HttpData::try_from(event.tags.clone()).map_err(|_| Error::InvalidEvent)?;

    let req_method = HttpMethod::from_str(method).map_err(|_| Error::MethodMismatch)?;
    if http_data.method != req_method {
        return Err(Error::MethodMismatch);
    }

    let event_url = Url::parse(&http_data.url.to_string()).map_err(|_| Error::UrlMismatch)?;
    if event_url != url {
        return Err(Error::UrlMismatch);
    }

    Ok(event)
}

#[cfg(feature = "axum")]
#[async_trait]
impl<S> FromRequestParts<S> for Nip98PubKey
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(auth) = parts.headers.get(AUTHORIZATION) {
            let auth = auth.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?.trim();
            let url = Url::parse(&parts.uri.to_string()).map_err(|_| StatusCode::UNAUTHORIZED)?;
            let event = validate_nip98(auth, url, parts.method.as_str())?;
            Ok(Nip98PubKey(event.pubkey))
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[cfg(feature = "actix")]
impl FromRequest for Nip98PubKey {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let auth = match req.headers().get("Authorization") {
            Some(auth) => match auth.to_str() {
                Ok(s) => s.trim(),
                Err(_) => {
                    return ready(Err(error::ErrorUnauthorized(
                        "invalid authorization header",
                    )))
                }
            },
            None => return ready(Err(error::ErrorUnauthorized("no authorization header"))),
        };
        let url = match Url::parse(&req.uri().to_string()) {
            Ok(u) => u,
            Err(_) => return ready(Err(error::ErrorUnauthorized("no authorization header"))),
        };
        let event = match validate_nip98(&auth, url, req.method().as_str()) {
            Ok(e) => e,
            Err(_) => return ready(Err(error::ErrorUnauthorized("no authorization header"))),
        };

        ready(Ok(Nip98PubKey(event.pubkey)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use nostr::{nips::nip98, EventBuilder, HttpMethod, Keys, Kind, UncheckedUrl};

    #[test]
    fn correctly_validates_nip98() {
        let keys = Keys::generate();
        let url = UncheckedUrl::from("https://example.com/");
        let tags = nip98::HttpData::new(url.clone(), HttpMethod::POST);
        let expected = EventBuilder::new(Kind::HttpAuth, "", &Vec::from(tags))
            .to_event(&keys)
            .unwrap()
            .as_json();
        let event = validate_nip98(
            &format!("Nostr {}", STANDARD.encode(&expected)),
            Url::parse(&url.to_string()).unwrap(),
            "POST",
        )
        .unwrap();

        assert_eq!(event.kind, Kind::HttpAuth);
        assert_eq!(event.as_json(), expected);
    }

    #[test]
    fn rejects_invalid_scheme() {
        let url = Url::parse("https://example.com").unwrap();
        let received = validate_nip98("Basic {}", url, "POST");

        assert!(
            matches!(received, Err(Error::InvalidScheme)),
            "received: {:?}",
            received
        );
    }

    #[test]
    fn rejects_empty_token() {
        let url = Url::parse("https://example.com").unwrap();
        let received = validate_nip98("Nostr ", url, "POST");

        assert!(
            matches!(received, Err(Error::InvalidEvent)),
            "received: {:?}",
            received
        );
    }

    #[test]
    fn rejects_invalid_base64_token() {
        let url = Url::parse("https://example.com").unwrap();
        let received = validate_nip98("Nostr zzz", url, "POST");

        assert!(
            matches!(received, Err(Error::InvalidBase64)),
            "received: {:?}",
            received
        );
    }

    #[test]
    fn rejects_non_nip98_kind() {
        let keys = Keys::generate();
        let url = UncheckedUrl::from("https://example.com");
        let tags = nip98::HttpData::new(url.clone(), HttpMethod::POST);
        let expected = EventBuilder::new(Kind::Metadata, "", &Vec::from(tags))
            .to_event(&keys)
            .unwrap()
            .as_json();
        let received = validate_nip98(
            &format!("Nostr {}", STANDARD.encode(&expected)),
            Url::parse(&url.to_string()).unwrap(),
            "POST",
        );

        assert!(
            matches!(received, Err(Error::InvalidEvent)),
            "received: {:?}",
            received
        );
    }

    #[test]
    fn rejects_created_at_over_10s() {
        let keys = Keys::generate();
        let url = UncheckedUrl::from("https://example.com");
        let tags = nip98::HttpData::new(url.clone(), HttpMethod::POST);

        let mut expected = EventBuilder::new(Kind::HttpAuth, "", &Vec::from(tags))
            .to_event(&keys)
            .unwrap();
        expected.created_at = expected.created_at - 60_i64;

        let expected = expected.as_json();
        let received = validate_nip98(
            &format!("Nostr {}", STANDARD.encode(&expected)),
            Url::parse(&url.to_string()).unwrap(),
            "POST",
        );

        assert!(
            matches!(received, Err(Error::TimestampOutOfRange)),
            "received: {:?}",
            received
        );
    }

    #[test]
    fn rejects_url_mismatch() {
        let keys = Keys::generate();
        let url = UncheckedUrl::from("https://example.com");
        let tags = nip98::HttpData::new(url, HttpMethod::POST);
        let expected = EventBuilder::new(Kind::HttpAuth, "", &Vec::from(tags))
            .to_event(&keys)
            .unwrap()
            .as_json();
        let url2 = Url::parse("https://anotherexample.com").unwrap();
        let received = validate_nip98(
            &format!("Nostr {}", STANDARD.encode(&expected)),
            url2,
            "POST",
        );

        assert!(
            matches!(received, Err(Error::UrlMismatch)),
            "received: {:?}",
            received
        );
    }

    #[test]
    fn rejects_method_mismatch() {
        let keys = Keys::generate();
        let url = UncheckedUrl::from("https://example.com");
        let tags = nip98::HttpData::new(url.clone(), HttpMethod::POST);
        let expected = EventBuilder::new(Kind::HttpAuth, "", &Vec::from(tags))
            .to_event(&keys)
            .unwrap()
            .as_json();
        let received = validate_nip98(
            &format!("Nostr {}", STANDARD.encode(&expected)),
            Url::parse(&url.to_string()).unwrap(),
            "GET",
        );

        assert!(
            matches!(received, Err(Error::MethodMismatch)),
            "received: {:?}",
            received
        );
    }
}
