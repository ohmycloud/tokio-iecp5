#![cfg(feature = "console")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_iecp5::console::Console;

async fn request(addr: std::net::SocketAddr, method: &str, headers: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let path = if method == "POST" {
        "/api/action"
    } else {
        "/api/state"
    };
    let request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len());
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn api_authentication_validation_and_local_only_cors() {
    let console = Console::new("test-http-secret-1234".into());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = console.router();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let auth = "X-IEC104-Token: test-http-secret-1234\r\n";
    let unauthorized = request(addr, "GET", "", "").await;
    assert!(unauthorized.starts_with("HTTP/1.1 401"));
    let ok = request(addr, "GET", auth, "").await;
    assert!(ok.starts_with("HTTP/1.1 200"));
    assert!(ok.contains("\"server_running\":false"));
    assert!(!ok.contains("test-http-secret"));
    let local = request(
        addr,
        "GET",
        &format!("{auth}Origin: http://localhost:8790\r\n"),
        "",
    )
    .await;
    assert!(local.contains("access-control-allow-origin: http://localhost:8790"));
    for origin in [
        "https://evil.example",
        "http://localhost.evil.example:8790",
        "null",
    ] {
        let other = request(addr, "GET", &format!("{auth}Origin: {origin}\r\n"), "").await;
        assert!(!other.contains("access-control-allow-origin:"));
    }
    let headers = format!("{auth}Content-Type: application/json\r\n");
    let bad = request(
        addr,
        "POST",
        &headers,
        r#"{"action":"server_start","address":"0.0.0.0:0","common_addr":1}"#,
    )
    .await;
    assert!(bad.starts_with("HTTP/1.1 400"));
    let good = request(
        addr,
        "POST",
        &headers,
        r#"{"action":"server_start","address":"127.0.0.1:0","common_addr":1}"#,
    )
    .await;
    assert!(good.starts_with("HTTP/1.1 200"));
    let invalid = request(
        addr,
        "POST",
        &headers,
        r#"{"action":"execute","ioa":100,"kind":"single","value":null}"#,
    )
    .await;
    assert!(invalid.starts_with("HTTP/1.1 422"));
    let parse = request(
        addr,
        "POST",
        &headers,
        r#"{"action":"parse","hex":"68 04 07 00 00 00"}"#,
    )
    .await;
    assert!(parse.starts_with("HTTP/1.1 200"));
    assert!(parse.contains("description"));
    console.shutdown().await;
    task.abort();
    let _ = task.await;
}
