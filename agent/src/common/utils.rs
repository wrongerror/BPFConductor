use std::hash::Hasher;
use std::result::Result;

use bytes::Bytes;
use fnv::FnvHasher;
use http_body_util::Empty;
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

pub async fn fetch_url(
    url: hyper::Uri,
) -> Result<Response<Incoming>, Box<dyn std::error::Error + Send + Sync>> {
    let host = url.host().expect("uri has no host");
    let port = url.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let authority = url.authority().unwrap().clone();

    let path = url.path();
    let req = Request::builder()
        .uri(path)
        .header(hyper::header::HOST, authority.as_str())
        .body(Empty::<Bytes>::new())?;

    let res = sender.send_request(req).await?;

    println!("Response: {}", res.status());
    println!("Headers: {:#?}\n", res.headers());
    println!("\n\nDone!");

    Ok(res)
}

pub fn fnv_hash(s: &str) -> u32 {
    let mut hasher = FnvHasher::default();
    hasher.write(s.as_bytes());
    hasher.finish() as u32
}
