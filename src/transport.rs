//! One official send, two bounded observations: original wire and SDK semantics.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use codex_http_client::{
    HttpTransport, Request, RequestBody, ReqwestTransport, Response, StreamResponse, TransportError,
};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// Bounded source error bytes, retained separately from the SDK's text diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct RawHttpError {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: Vec<u8>,
    pub complete: bool,
    pub retry_after: Option<codex_http_client::RetryAfter>,
}
impl std::fmt::Debug for RawHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawHttpError")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .field("complete", &self.complete)
            .finish()
    }
}
impl RawHttpError {
    pub fn into_response(self) -> axum::response::Response {
        use axum::{body::Body, response::IntoResponse};
        let mut bytes = self.body;
        if self.complete
            && let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes)
        {
            let before = value.clone();
            crate::response_projection::sanitize_http_error(&mut value);
            if before != value {
                bytes = serde_json::to_vec(&value).expect("JSON value");
            }
        }
        let body = if self.complete {
            Body::from(bytes)
        } else {
            Body::from_stream(async_stream::stream! {
                yield Ok::<Bytes,std::io::Error>(Bytes::from(bytes));
                tokio::task::yield_now().await;
                yield Err(std::io::Error::other("upstream error body incomplete"));
            })
        };
        let mut response = (self.status, body).into_response();
        response
            .headers_mut()
            .extend(crate::response_projection::project_response_headers(
                &self.headers,
            ));
        for name in [
            http::header::CONTENT_TYPE,
            http::header::CONTENT_ENCODING,
            http::header::CONTENT_LANGUAGE,
        ] {
            if let Some(value) = self.headers.get(&name) {
                response.headers_mut().insert(name, value.clone());
            }
        }
        response
    }
}

/// The SDK still prepares the request, compression, auth and telemetry. Only
/// the byte-preserving send is adapted: ReqwestTransport decodes error bodies.
pub(crate) async fn send_prepared(
    client: &reqwest::Client,
    request: &Request,
) -> Result<reqwest::Response, TransportError> {
    let prepared = request
        .prepare_body_for_send()
        .map_err(TransportError::Build)?;
    let mut builder = client
        .request(request.method.clone(), &request.url)
        .headers(prepared.headers);
    if let Some(timeout) = request.timeout {
        builder = builder.timeout(timeout);
    }
    if let Some(body) = prepared.body {
        builder = builder.body(body);
    }
    builder.send().await.map_err(map_network_error)
}
fn map_network_error(error: reqwest::Error) -> TransportError {
    let error = error.without_url();
    if error.is_connect() {
        TransportError::Connection(error.into())
    } else if error.is_timeout() {
        TransportError::Timeout
    } else {
        TransportError::Network(error.to_string())
    }
}
pub(crate) async fn read_http_error(response: reqwest::Response, max_bytes: usize) -> RawHttpError {
    let mut error = RawHttpError {
        status: response.status(),
        retry_after: codex_http_client::RetryAfter::from_headers(response.headers()),
        headers: response.headers().clone(),
        body: Vec::new(),
        complete: true,
    };
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(chunk) if error.body.len().saturating_add(chunk.len()) <= max_bytes => {
                error.body.extend_from_slice(&chunk)
            }
            _ => {
                error.complete = false;
                break;
            }
        }
    }
    error
}

pub struct WireResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub bytes: codex_http_client::ByteStream,
    pub logical_sha: String,
    pub wire_sha: String,
}

#[derive(Clone)]
pub struct ObservedTransport {
    inner: ReqwestTransport,
    client: reqwest::Client,
    http_error: Arc<Mutex<Option<RawHttpError>>>,
    response: Arc<Mutex<Option<oneshot::Sender<WireResponse>>>>,
    cancel: CancellationToken,
    timeout: Duration,
}

impl ObservedTransport {
    pub fn new(
        client: reqwest::Client,
        timeout: Duration,
    ) -> (Self, oneshot::Receiver<WireResponse>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                inner: ReqwestTransport::new(client.clone()),
                client,
                http_error: Arc::new(Mutex::new(None)),
                response: Arc::new(Mutex::new(Some(tx))),
                cancel: CancellationToken::new(),
                timeout,
            },
            rx,
        )
    }
    pub fn http_error(&self) -> Arc<Mutex<Option<RawHttpError>>> {
        self.http_error.clone()
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
}

impl HttpTransport for ObservedTransport {
    async fn execute(&self, mut request: Request) -> Result<Response, TransportError> {
        request.timeout = Some(self.timeout);
        request.response_body_limit_bytes = Some(64 * 1024 * 1024);
        self.inner.execute(request).await
    }

    async fn stream(&self, mut request: Request) -> Result<StreamResponse, TransportError> {
        request.timeout = Some(self.timeout);
        request.response_body_limit_bytes = Some(64 * 1024 * 1024);
        let logical_sha = logical_body_hash(&request)?;
        let prepared = request
            .into_prepared()
            .map_err(|_| TransportError::Build("official request preparation failed".into()))?;
        let wire_sha = body_hash(&prepared);
        let response = send_prepared(&self.client, &prepared).await?;
        if !response.status().is_success() {
            let raw = read_http_error(response, 64 * 1024 * 1024).await;
            let error = TransportError::Http {
                status: raw.status,
                url: None,
                headers: Some(raw.headers.clone()),
                body: raw
                    .complete
                    .then(|| String::from_utf8(raw.body.clone()).ok())
                    .flatten(),
                retry_after: raw.retry_after,
            };
            *self
                .http_error
                .lock()
                .map_err(|_| TransportError::Build("error observer unavailable".into()))? =
                Some(raw);
            return Err(error);
        }
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = async_stream::stream! {
            let mut source = response.bytes_stream();
            let mut received = 0usize;
            while let Some(chunk) = source.next().await {
                match chunk {
                    Ok(chunk) => {
                        received = received.saturating_add(chunk.len());
                        if received > 64*1024*1024 { yield Err(TransportError::ResponseTooLarge {max_bytes:64*1024*1024}); break; }
                        yield Ok(chunk);
                    }
                    Err(error) => { yield Err(map_network_error(error)); break; }
                }
            }
        };
        let response = StreamResponse {
            status,
            headers,
            bytes: Box::pin(bytes),
        };
        let (tx, rx) = mpsc::channel::<Result<Bytes, TransportError>>(32);
        let raw = async_stream::stream! { let mut rx=rx; while let Some(chunk)=rx.recv().await { yield chunk; } };
        let sender = self
            .response
            .lock()
            .map_err(|_| TransportError::Build("wire observer unavailable".into()))?
            .take()
            .ok_or_else(|| {
                TransportError::Build("wire observer cannot observe a second send".into())
            })?;
        sender
            .send(WireResponse {
                status: response.status,
                headers: response.headers.clone(),
                bytes: Box::pin(raw),
                logical_sha,
                wire_sha,
            })
            .map_err(|_| TransportError::Build("wire observer cancelled".into()))?;
        let cancel = self.cancel.clone();
        let stream = async_stream::stream! {
            let mut upstream=response.bytes;
            loop {
                let next=tokio::select! { _=cancel.cancelled()=>break, next=upstream.next()=>next };
                let Some(next)=next else { break; };
                match next {
                    Ok(chunk)=>{
                        let sent=tokio::select! { _=cancel.cancelled()=>break, sent=tx.send(Ok(chunk.clone()))=>sent };
                        if sent.is_err() { break; }
                        yield Ok(chunk);
                    }
                    Err(error)=>{
                        let _=tx.send(Err(TransportError::Network("upstream stream failed".into()))).await;
                        yield Err(error); break;
                    }
                }
            }
        };
        Ok(StreamResponse {
            status: response.status,
            headers: response.headers,
            bytes: Box::pin(stream),
        })
    }
}

fn body_hash(request: &Request) -> String {
    let bytes = match &request.body {
        Some(RequestBody::EncodedJson(body)) => body.as_bytes().to_vec(),
        Some(RequestBody::Json(body)) => serde_json::to_vec(body).unwrap_or_default(),
        Some(RequestBody::Raw(body)) => body.to_vec(),
        None => Vec::new(),
    };
    format!("{:x}", Sha256::digest(bytes))
}

/// Dropping a downstream stream immediately closes the source and semantic task.
pub struct ParserGuard {
    pub task: tokio::task::JoinHandle<()>,
    pub cancel: CancellationToken,
}
impl Drop for ParserGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

#[expect(
    clippy::result_large_err,
    reason = "The official HttpTransport contract returns TransportError directly"
)]
fn logical_body_hash(request: &Request) -> Result<String, TransportError> {
    // EndpointSession prepares compression before auth.apply_auth and transport.
    // Observe the actual logical bytes, even when the public SDK supplied zstd.
    if request
        .headers
        .get(http::header::CONTENT_ENCODING)
        .is_some_and(|v| v == "zstd")
    {
        use std::io::Read;
        let encoded = match &request.body {
            Some(RequestBody::EncodedJson(v)) => v.as_bytes(),
            Some(RequestBody::Raw(v)) => v.as_ref(),
            _ => return Err(TransportError::Build("compressed body unavailable".into())),
        };
        let decoder = zstd::stream::read::Decoder::new(encoded)
            .map_err(|_| TransportError::Build("compressed request invalid".into()))?;
        let mut decoded = Vec::new();
        decoder
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut decoded)
            .map_err(|_| TransportError::Build("compressed request invalid".into()))?;
        if decoded.len() > 64 * 1024 * 1024 {
            return Err(TransportError::Build(
                "logical request budget exceeded".into(),
            ));
        }
        return Ok(format!("{:x}", Sha256::digest(decoded)));
    }
    Ok(body_hash(request))
}
