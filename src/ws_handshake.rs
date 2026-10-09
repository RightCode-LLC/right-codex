//! Preserve rejected HTTP upgrade bodies on the same established socket.
//! The pinned tungstenite client still generates and validates the WS handshake.
use crate::{transport::RawHttpError, ws_transport::AsyncIo};
use futures_util::future::BoxFuture;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: usize = 64 * 1024 * 1024;
const MAX_CHUNK_LINE: usize = 8192;
pub(crate) type Capture = Arc<Mutex<Option<RawHttpError>>>;
type ReadResult = io::Result<(Box<dyn AsyncIo>, Vec<u8>)>;

pub(crate) struct Reader {
    stream: Option<Box<dyn AsyncIo>>,
    reading: Option<BoxFuture<'static, ReadResult>>,
    prefix: Vec<u8>,
    offset: usize,
    ready: bool,
    capture: Capture,
}
impl Reader {
    pub(crate) fn new(stream: Box<dyn AsyncIo>, capture: Capture) -> Self {
        Self {
            stream: Some(stream),
            reading: None,
            prefix: Vec::new(),
            offset: 0,
            ready: false,
            capture,
        }
    }
}
impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.ready {
            if self.reading.is_none() {
                let Some(stream) = self.stream.take() else {
                    return Poll::Ready(Err(io::Error::other("handshake reader unavailable")));
                };
                self.reading = Some(Box::pin(read_response(stream, self.capture.clone())));
            }
            let future = self.reading.as_mut().expect("handshake read future");
            match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok((stream, prefix))) => {
                    self.stream = Some(stream);
                    self.prefix = prefix;
                    self.reading = None;
                    self.ready = true;
                }
            }
        }
        if self.offset < self.prefix.len() {
            let end = (self.offset + out.remaining()).min(self.prefix.len());
            out.put_slice(&self.prefix[self.offset..end]);
            self.offset = end;
            return Poll::Ready(Ok(()));
        }
        Pin::new(self.stream.as_mut().expect("ready stream")).poll_read(cx, out)
    }
}
impl AsyncWrite for Reader {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_write(cx, bytes),
            None => Poll::Ready(Err(io::Error::other("handshake response read in progress"))),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_flush(cx),
            None => Poll::Ready(Err(io::Error::other("handshake response read in progress"))),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}
async fn read_response(mut stream: Box<dyn AsyncIo>, capture: Capture) -> ReadResult {
    let mut bytes = Vec::new();
    let head_end = loop {
        if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
            break end + 4;
        }
        if bytes.len() >= MAX_HEAD {
            return Err(io::Error::other("upstream handshake header too large"));
        }
        let mut chunk = [0; 8192];
        let capacity = chunk.len().min(MAX_HEAD - bytes.len());
        let count = stream.read(&mut chunk[..capacity]).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream handshake header incomplete",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
    };
    let mut entries = [httparse::EMPTY_HEADER; 256];
    let mut response = httparse::Response::new(&mut entries);
    response
        .parse(&bytes[..head_end])
        .map_err(|_| io::Error::other("invalid upstream handshake header"))?;
    let status = StatusCode::from_u16(
        response
            .code
            .ok_or_else(|| io::Error::other("missing handshake status"))?,
    )
    .map_err(io::Error::other)?;
    if status == StatusCode::SWITCHING_PROTOCOLS {
        return Ok((stream, bytes));
    }
    let mut headers = HeaderMap::new();
    for entry in response.headers {
        headers.append(
            HeaderName::from_bytes(entry.name.as_bytes()).map_err(io::Error::other)?,
            HeaderValue::from_bytes(entry.value).map_err(io::Error::other)?,
        );
    }
    *capture
        .lock()
        .map_err(|_| io::Error::other("handshake capture unavailable"))? = Some(RawHttpError {
        status,
        retry_after: codex_http_client::RetryAfter::from_headers(&headers),
        headers: headers.clone(),
        body: Vec::new(),
        complete: false,
    });
    let tail = bytes.split_off(head_end);
    // Any failure/cancellation leaves the actual status and observed prefix in
    // Capture. The outer timeout returns that incomplete HTTP response.
    let mut input = tokio::io::BufReader::new(std::io::Cursor::new(tail).chain(stream));
    let complete = read_body(&mut input, status, &headers, &capture)
        .await
        .is_ok();
    if let Ok(mut raw) = capture.lock()
        && let Some(raw) = raw.as_mut()
    {
        raw.complete = complete;
    }
    let (_, stream) = input.into_inner().into_inner();
    // The native parser receives the original header and makes the same status
    // decision. Error body ownership remains in Capture, never in its tail.
    Ok((stream, bytes))
}
fn append(capture: &Capture, bytes: &[u8]) -> io::Result<()> {
    let mut state = capture
        .lock()
        .map_err(|_| io::Error::other("handshake capture unavailable"))?;
    let raw = state
        .as_mut()
        .ok_or_else(|| io::Error::other("missing handshake capture"))?;
    let remaining = MAX_BODY.saturating_sub(raw.body.len());
    raw.body
        .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
    if bytes.len() > remaining {
        return Err(io::Error::other("upstream error body too large"));
    }
    Ok(())
}
async fn read_body<R: tokio::io::AsyncBufRead + Unpin>(
    input: &mut R,
    status: StatusCode,
    headers: &HeaderMap,
    capture: &Capture,
) -> io::Result<()> {
    if status.is_informational() || matches!(status.as_u16(), 204 | 304) {
        return Ok(());
    }
    let transfers: Vec<_> = headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .collect();
    if !transfers.is_empty() {
        if transfers.len() != 1 || !transfers[0].as_bytes().eq_ignore_ascii_case(b"chunked") {
            return Err(io::Error::other("unsupported transfer encoding"));
        }
        loop {
            let chunk_line = line(input).await?;
            let size = std::str::from_utf8(&chunk_line)
                .ok()
                .and_then(|s| s.trim().split(';').next())
                .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
                .ok_or_else(|| io::Error::other("invalid chunk size"))?;
            if size == 0 {
                let mut trailer_bytes = 0;
                loop {
                    let trailer = line(input).await?;
                    trailer_bytes += trailer.len();
                    if trailer_bytes > MAX_HEAD {
                        return Err(io::Error::other("upstream trailers too large"));
                    }
                    if trailer == b"\r\n" {
                        return Ok(());
                    }
                }
            }
            exact(input, size, capture).await?;
            let mut terminator = [0; 2];
            input.read_exact(&mut terminator).await?;
            if terminator != *b"\r\n" {
                return Err(io::Error::other("invalid chunk terminator"));
            }
        }
    }
    let lengths: Vec<_> = headers
        .get_all(http::header::CONTENT_LENGTH)
        .iter()
        .map(|v| v.to_str().ok().and_then(|s| s.parse::<usize>().ok()))
        .collect();
    if !lengths.is_empty() {
        let length = lengths[0].ok_or_else(|| io::Error::other("invalid content length"))?;
        if lengths.iter().any(|v| *v != Some(length)) {
            return Err(io::Error::other("conflicting content lengths"));
        }
        return exact(input, length, capture).await;
    }
    let mut buffer = [0; 8192];
    loop {
        let count = input.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        append(capture, &buffer[..count])?;
    }
}
async fn line<R: tokio::io::AsyncBufRead + Unpin>(input: &mut R) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let count = input
        .take((MAX_CHUNK_LINE + 1) as u64)
        .read_until(b'\n', &mut line)
        .await?;
    if count == 0 || count > MAX_CHUNK_LINE || !line.ends_with(b"\r\n") {
        return Err(io::Error::other("invalid chunk line"));
    }
    Ok(line)
}
async fn exact<R: AsyncRead + Unpin>(
    input: &mut R,
    mut remaining: usize,
    capture: &Capture,
) -> io::Result<()> {
    let mut buffer = [0; 8192];
    while remaining > 0 {
        let capacity = remaining.min(buffer.len());
        let count = input.read(&mut buffer[..capacity]).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream error body incomplete",
            ));
        }
        append(capture, &buffer[..count])?;
        remaining -= count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn header_limit_rejects_before_unbounded_buffering() {
        let (client, mut server) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            let bytes = format!(
                "HTTP/1.1 429 Too Many Requests\r\nX-Large: {}",
                "x".repeat(MAX_HEAD)
            );
            let _ = server.write_all(bytes.as_bytes()).await;
        });
        let capture = Arc::new(Mutex::new(None));
        assert!(
            read_response(Box::new(client), capture.clone())
                .await
                .is_err()
        );
        assert!(capture.lock().unwrap().is_none());
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn truncated_content_length_keeps_exact_observed_prefix() {
        let (client, mut server) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            server
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 20\r\n\r\nactual prefix",
                )
                .await
                .unwrap();
        });
        let capture = Arc::new(Mutex::new(None));
        read_response(Box::new(client), capture.clone())
            .await
            .unwrap();
        let raw = capture.lock().unwrap().take().unwrap();
        assert_eq!(raw.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(raw.body, b"actual prefix");
        assert!(!raw.complete);
        writer.await.unwrap();
    }
}
