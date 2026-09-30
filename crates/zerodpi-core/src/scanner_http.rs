use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// Download sampling shared by both scanners.
pub(crate) async fn measure_download<S>(
    stream: &mut S,
    req_start: Instant,
    cap: usize,
    timeout: Duration,
) -> (Option<u64>, Option<f64>, Option<u16>)
where
    S: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; cap.min(8 * 1024)];
    let mut total_read = 0usize;
    let mut ttfb = None;
    let mut status = None;
    let mut status_line = Vec::with_capacity(128);
    let mut status_line_complete = false;
    let deadline = tokio::time::Instant::from_std(req_start) + timeout;

    while total_read < cap {
        let read_len = buf.len().min(cap - total_read);
        match tokio::time::timeout_at(deadline, stream.read(&mut buf[..read_len])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                if ttfb.is_none() {
                    ttfb = Some(req_start.elapsed().as_millis() as u64);
                }
                if !status_line_complete {
                    let bytes = &buf[..n];
                    let end = bytes.iter().position(|b| *b == b'\n');
                    let take = end.unwrap_or(n).min(1024 - status_line.len());
                    status_line.extend_from_slice(&bytes[..take]);
                    if end.is_some() || status_line.len() == 1024 {
                        status_line_complete = true;
                        if end.is_some() {
                            status = std::str::from_utf8(&status_line)
                                .ok()
                                .and_then(parse_http_status);
                        }
                    }
                }
                total_read += n;
            }
        }
    }

    let speed = if total_read > 0 {
        let elapsed = req_start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            Some(total_read as f64 / elapsed)
        } else {
            None
        }
    } else {
        None
    };
    (ttfb, speed, status)
}

pub(crate) async fn measure_upload<S>(
    stream: &mut S,
    host: &str,
    upload_path: &str,
    upload_bytes: usize,
    timeout: Duration,
) -> Option<f64>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "POST {upload_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: zerodpi-scanner/0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {upload_bytes}\r\n\r\n"
    );

    if !matches!(
        tokio::time::timeout(timeout, stream.write_all(req.as_bytes())).await,
        Ok(Ok(()))
    ) {
        return None;
    }

    let result = tokio::time::timeout(timeout, async {
        let chunk = vec![0u8; upload_bytes.min(16 * 1024)];
        let start = Instant::now();
        let mut remaining = upload_bytes;
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            stream.write_all(&chunk[..n]).await?;
            remaining -= n;
        }
        stream.flush().await?;

        let mut response = [0u8; 1024];
        let mut response_len = 0usize;
        while response_len < response.len() {
            let n = stream.read(&mut response[response_len..]).await?;
            if n == 0 {
                break;
            }
            response_len += n;
            if response[..response_len].contains(&b'\n') {
                break;
            }
        }

        if response_len == 0 {
            return Ok::<Option<Duration>, std::io::Error>(None);
        }

        let line_end = response[..response_len]
            .iter()
            .position(|b| *b == b'\n')
            .unwrap_or(response_len);
        let mut status_line = &response[..line_end];
        if status_line.ends_with(b"\r") {
            status_line = &status_line[..status_line.len() - 1];
        }

        let status = std::str::from_utf8(status_line)
            .ok()
            .and_then(parse_http_status);
        if status.is_none() {
            return Ok(None);
        }

        Ok(Some(start.elapsed()))
    })
    .await;

    let elapsed = match result {
        Ok(Ok(Some(elapsed))) => elapsed.as_secs_f64(),
        _ => return None,
    };

    if elapsed > 0.0 {
        Some(upload_bytes as f64 / elapsed)
    } else {
        None
    }
}

pub(crate) fn parse_http_status(text: &str) -> Option<u16> {
    let line = text.lines().next()?;
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn download_parses_split_status_line_with_binary_body() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            server.write_all(b"HTTP/1.").await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            server.write_all(b"1 200 OK\r\n\r\n\xff\xfe").await.unwrap();
        });
        let (ttfb, speed, status) =
            measure_download(&mut client, Instant::now(), 1024, Duration::from_secs(1)).await;
        task.await.unwrap();
        assert!(ttfb.is_some());
        assert!(speed.is_some());
        assert_eq!(status, Some(200));
    }

    #[tokio::test]
    async fn download_timeout_bounds_entire_sample() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            for _ in 0..30 {
                if server.write_all(b"x").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let sample = tokio::time::timeout(
            Duration::from_millis(200),
            measure_download(&mut client, Instant::now(), 1024, Duration::from_millis(40)),
        )
        .await;
        task.abort();
        let _ = task.await;
        assert!(
            sample.is_ok(),
            "a trickling peer kept extending the download timeout"
        );
        assert!(sample.unwrap().0.is_some());
    }

    const UPLOAD_BYTES: usize = 1024;

    async fn consume_upload<S>(server: &mut S, upload_bytes: usize)
    where
        S: AsyncRead + Unpin,
    {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 256];
        let header_end = loop {
            let n = server.read(&mut tmp).await.unwrap();
            assert_ne!(n, 0);
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };

        let already_read = buf.len().saturating_sub(header_end);
        let mut remaining = upload_bytes.saturating_sub(already_read);
        while remaining > 0 {
            let read_len = remaining.min(tmp.len());
            let n = server.read(&mut tmp[..read_len]).await.unwrap();
            assert_ne!(n, 0);
            remaining -= n;
        }
    }

    #[tokio::test]
    async fn upload_rate_waits_for_http_response() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            consume_upload(&mut server, UPLOAD_BYTES).await;
            tokio::time::sleep(Duration::from_millis(60)).await;
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let speed = measure_upload(
            &mut client,
            "example.com",
            "/",
            UPLOAD_BYTES,
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        server_task.await.unwrap();
        assert!(speed > 0.0);
        assert!(speed < 50_000.0, "speed was {speed}");
    }

    #[tokio::test]
    async fn upload_rate_requires_http_response() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            consume_upload(&mut server, UPLOAD_BYTES).await;
        });

        let speed = measure_upload(
            &mut client,
            "example.com",
            "/",
            UPLOAD_BYTES,
            Duration::from_secs(1),
        )
        .await;

        server_task.await.unwrap();
        assert_eq!(speed, None);
    }

    #[test]
    fn parse_http_status_rejects_non_http_response() {
        assert_eq!(parse_http_status("not http"), None);
    }
}
