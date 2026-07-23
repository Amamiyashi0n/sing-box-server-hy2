use std::{
    path::{Component, Path, PathBuf},
    sync::LazyLock,
};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header};
use percent_encoding::percent_decode_str;

use crate::config::MasqueradeConfig;

static PROXY_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

pub struct MasqueradeResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

pub async fn response(
    config: Option<&MasqueradeConfig>,
    request: &Request<()>,
    body: Bytes,
) -> Result<MasqueradeResponse> {
    match config {
        None => Ok(MasqueradeResponse {
            status: StatusCode::NOT_FOUND,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }),
        Some(MasqueradeConfig::String {
            status_code,
            headers,
            content,
        }) => {
            let mut output_headers = HeaderMap::new();
            for (name, values) in headers {
                let name = HeaderName::from_bytes(name.as_bytes())?;
                for value in values {
                    output_headers.append(name.clone(), HeaderValue::from_str(value)?);
                }
            }
            Ok(MasqueradeResponse {
                status: StatusCode::from_u16(*status_code)?,
                headers: output_headers,
                body: Bytes::copy_from_slice(content.as_bytes()),
            })
        }
        Some(MasqueradeConfig::File { directory }) => file_response(directory, request).await,
        Some(MasqueradeConfig::Proxy { url, rewrite_host }) => {
            proxy_response(url, *rewrite_host, request, body).await
        }
    }
}

async fn file_response(directory: &str, request: &Request<()>) -> Result<MasqueradeResponse> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return Ok(MasqueradeResponse {
            status: StatusCode::METHOD_NOT_ALLOWED,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        });
    }
    let decoded = percent_decode_str(request.uri().path())
        .decode_utf8()
        .context("decode masquerade request path")?;
    let relative = Path::new(decoded.trim_start_matches('/'));
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        bail!("unsafe masquerade request path");
    }
    let mut path = PathBuf::from(directory);
    path.push(relative);
    if tokio::fs::metadata(&path)
        .await
        .is_ok_and(|metadata| metadata.is_dir())
    {
        path.push("index.html");
    }
    let Ok(body) = tokio::fs::read(&path).await else {
        return Ok(MasqueradeResponse {
            status: StatusCode::NOT_FOUND,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        });
    };
    let mut headers = HeaderMap::new();
    if let Some(mime) = mime_guess::from_path(&path).first() {
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(mime.as_ref())?);
    }
    Ok(MasqueradeResponse {
        status: StatusCode::OK,
        headers,
        body: if request.method() == Method::HEAD {
            Bytes::new()
        } else {
            Bytes::from(body)
        },
    })
}

async fn proxy_response(
    target: &str,
    rewrite_host: bool,
    request: &Request<()>,
    body: Bytes,
) -> Result<MasqueradeResponse> {
    let mut url = reqwest::Url::parse(target)?;
    let base_path = url.path().trim_end_matches('/');
    let request_path = request.uri().path().trim_start_matches('/');
    url.set_path(&format!("{base_path}/{request_path}"));
    url.set_query(request.uri().query());

    let mut outbound = PROXY_CLIENT.request(request.method().clone(), url);
    for (name, value) in request.headers() {
        if !is_hop_by_hop(name) && name != header::HOST && name != header::CONTENT_LENGTH {
            outbound = outbound.header(name, value);
        }
    }
    if let (false, Some(authority)) = (rewrite_host, request.uri().authority()) {
        outbound = outbound.header(header::HOST, authority.as_str());
    }
    let response = outbound
        .body(body)
        .send()
        .await
        .context("forward masquerade request")?;
    let status = response.status();
    let mut headers = HeaderMap::new();
    for (name, value) in response.headers() {
        if !is_hop_by_hop(name) {
            headers.append(name.clone(), value.clone());
        }
    }
    let body = response.bytes().await.context("read masquerade response")?;
    Ok(MasqueradeResponse {
        status,
        headers,
        body,
    })
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    name == header::CONNECTION
        || name == header::TRANSFER_ENCODING
        || name == header::UPGRADE
        || name.as_str().eq_ignore_ascii_case("keep-alive")
        || name.as_str().eq_ignore_ascii_case("proxy-connection")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn string_response_keeps_repeated_headers() {
        let config = MasqueradeConfig::String {
            status_code: 201,
            headers: [(
                "x-test".to_owned(),
                vec!["one".to_owned(), "two".to_owned()],
            )]
            .into(),
            content: "hello".to_owned(),
        };
        let request = Request::get("https://example.com/").body(()).unwrap();
        let response = response(Some(&config), &request, Bytes::new())
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.headers.get_all("x-test").iter().count(), 2);
        assert_eq!(response.body, "hello");
    }

    #[tokio::test]
    async fn file_response_rejects_encoded_parent_path() {
        let directory = tempfile::tempdir().unwrap();
        let request = Request::get("https://example.com/%2e%2e/secret")
            .body(())
            .unwrap();
        assert!(
            file_response(directory.path().to_str().unwrap(), &request)
                .await
                .is_err()
        );
    }
}
