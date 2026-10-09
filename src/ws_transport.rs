//! Fixed official WebSocket dialer with a per-account proxy route; no env proxy.
mod dialer;

use codex_http_client::{OutboundProxyRoute, build_rustls_client_config_with_custom_ca};
use futures::future::Either;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::extensions::{
    ExtensionsConfig, compression::deflate::DeflateConfig,
};
use tokio_tungstenite::tungstenite::handshake::client::Response;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error, client::IntoClientRequest};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncIo for T {}
pub type ConnectionInner = Either<
    WebSocketStream<MaybeTlsStream<TcpStream>>,
    WebSocketStream<MaybeTlsStream<Box<dyn AsyncIo>>>,
>;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TcpNodelay {
    Enabled,
}

pub async fn connect(
    url: &str,
    headers: http::HeaderMap,
    proxy: Option<&str>,
    capture: crate::ws_handshake::Capture,
) -> Result<(ConnectionInner, Response), Error> {
    let mut request = url.into_client_request()?;
    request.headers_mut().extend(headers);
    let mut extensions = ExtensionsConfig::default();
    extensions.permessage_deflate = Some(DeflateConfig::default());
    let mut config = WebSocketConfig::default();
    config.extensions = extensions;
    config.max_message_size = Some(64 * 1024 * 1024);
    config.max_frame_size = Some(64 * 1024 * 1024);
    let tls = build_rustls_client_config_with_custom_ca()
        .map_err(|_| Error::Io(std::io::Error::other("WebSocket TLS configuration failed")))?;
    let route = match proxy {
        Some(value) => OutboundProxyRoute::Proxy {
            url: value.to_owned(),
            no_proxy: None,
        },
        None => OutboundProxyRoute::Direct,
    };
    dialer::connect(
        request,
        config,
        Some(tls),
        route,
        TcpNodelay::Enabled,
        false,
        capture,
    )
    .await
}
