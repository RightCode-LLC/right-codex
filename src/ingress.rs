//! Official OAuth HTTP fallback sends zstd JSON. Admission runs before this
//! decoder; both compressed and expanded bodies have the same explicit bound.
use std::io::{Cursor, Read};

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::{StatusCode, header};

pub(crate) const BODY_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum DecodeError {
    Invalid,
    TooLarge,
}

fn expand(bytes: &[u8], limit: usize) -> Result<Vec<u8>, DecodeError> {
    let mut decoder =
        zstd::stream::read::Decoder::new(Cursor::new(bytes)).map_err(|_| DecodeError::Invalid)?;
    decoder
        .window_log_max(27)
        .map_err(|_| DecodeError::Invalid)?;
    let mut output = Vec::new();
    decoder
        .take(limit as u64 + 1)
        .read_to_end(&mut output)
        .map_err(|_| DecodeError::Invalid)?;
    if output.len() > limit {
        return Err(DecodeError::TooLarge);
    }
    Ok(output)
}

fn failure(status: StatusCode, code: &'static str, en: &'static str, zh: &'static str) -> Response {
    crate::gateway::error(status, code, en, zh)
}

pub(crate) async fn decode_json(request: Request, next: Next) -> Response {
    let encodings = request.headers().get_all(header::CONTENT_ENCODING);
    let mut values = encodings.iter();
    let encoding = values.next();
    if values.next().is_some() {
        return failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_content_encoding",
            "One zstd or identity content encoding is required",
            "仅接受一个 zstd 或 identity 内容编码",
        );
    }
    match encoding.and_then(|value| value.to_str().ok()) {
        None if encoding.is_none() => return next.run(request).await,
        Some("identity") => return next.run(request).await,
        Some("zstd") => {}
        _ => {
            return failure(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_content_encoding",
                "Only zstd or identity content encoding is supported",
                "仅支持 zstd 或 identity 内容编码",
            );
        }
    }
    let (mut parts, body) = request.into_parts();
    let bytes = match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return failure(
                StatusCode::PAYLOAD_TOO_LARGE,
                "compressed_body_limit",
                "Compressed request body exceeded its limit or could not be read",
                "压缩请求体超出限制或读取失败",
            );
        }
    };
    let decoded = tokio::task::spawn_blocking(move || expand(&bytes, BODY_LIMIT)).await;
    let body = match decoded {
        Ok(Ok(body)) => body,
        Ok(Err(DecodeError::TooLarge)) => {
            return failure(
                StatusCode::PAYLOAD_TOO_LARGE,
                "expanded_body_limit",
                "Expanded request body exceeds the limit",
                "解压后的请求体超过限制",
            );
        }
        _ => {
            return failure(
                StatusCode::BAD_REQUEST,
                "invalid_compressed_body",
                "The zstd request body is invalid or incomplete",
                "zstd 请求体无效或不完整",
            );
        }
    };
    parts.headers.remove(header::CONTENT_ENCODING);
    parts.headers.remove(header::CONTENT_LENGTH);
    next.run(Request::from_parts(parts, Body::from(body))).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, middleware, routing::post};
    use http::Request as HttpRequest;
    use tower::ServiceExt;

    #[test]
    fn bounded_zstd_rejects_bombs_truncation_and_trailing_garbage() {
        let encoded = zstd::stream::encode_all(Cursor::new(b"{\"input\":[]}"), 3).unwrap();
        assert_eq!(expand(&encoded, 64).unwrap(), b"{\"input\":[]}");
        assert_eq!(expand(&encoded, 4), Err(DecodeError::TooLarge));
        assert_eq!(
            expand(&encoded[..encoded.len() - 1], 64),
            Err(DecodeError::Invalid)
        );
        let mut trailing = encoded;
        trailing.extend_from_slice(b"not a zstd frame");
        assert_eq!(expand(&trailing, 64), Err(DecodeError::Invalid));
    }

    #[tokio::test]
    async fn native_compressed_json_is_decoded_before_extraction_and_bad_encodings_reject() {
        let app = Router::new()
            .route(
                "/",
                post(
                    |axum::Json(value): axum::Json<serde_json::Value>| async move {
                        assert_eq!(value["input"], serde_json::json!([]));
                        StatusCode::OK
                    },
                ),
            )
            .layer(middleware::from_fn(decode_json));
        let encoded = zstd::stream::encode_all(Cursor::new(b"{\"input\":[]}"), 3).unwrap();
        for (encoding, data, expected) in [
            ("zstd", encoded, StatusCode::OK),
            ("zstd", b"broken".to_vec(), StatusCode::BAD_REQUEST),
            (
                "gzip",
                b"broken".to_vec(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
        ] {
            let request = HttpRequest::post("/")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_ENCODING, encoding)
                .body(Body::from(data))
                .unwrap();
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                expected
            );
        }
    }
}
