use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus_client::{encoding::text::encode, metrics::counter::Counter, registry::Registry};
use tokio::net::TcpListener;

/// Start a HTTP server to report metrics.
pub async fn start_metrics_server(
    addr: SocketAddr,
    registry: Registry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(&addr).await?;
    let registry = Arc::new(registry);
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let registry = registry.clone();
        tokio::task::spawn(async move {
            let handler = maker_handler(registry);
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handler))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}

fn maker_handler(
    registry: Arc<Registry>,
) -> impl Fn(
    Request<hyper::body::Incoming>,
) -> Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send>> {
    move |_req: Request<hyper::body::Incoming>| {
        let reg = registry.clone();
        Box::pin(async move {
            let mut buf = String::new();
            match encode(&mut buf, &reg.clone()) {
                Ok(_) => Ok(Response::builder()
                    .header(
                        hyper::header::CONTENT_TYPE,
                        "application/openmetrics-text; version=1.0.0; charset=utf-8",
                    )
                    .body(Full::from(buf))
                    .unwrap()),
                Err(_) => {
                    // Handle or ignore the error here.
                    // For example, you can return an empty response with a status code of 500.
                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::from(Bytes::new()))
                        .unwrap())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr};
    use std::string::String;

    use hyper::body::Buf;
    use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
    use prometheus_client::metrics::family::Family;

    use crate::utils::fetch_url;

    use super::*;

    #[tokio::test]
    async fn test_start_metrics_server() {
        let metrics_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);

        // Create a metric registry.
        //
        // Note the angle brackets to make sure to use the default (dynamic
        // dispatched boxed metric) for the generic type parameter.
        let mut registry = <Registry>::default();

        // Define a type representing a metric label set, i.e. a key value pair.
        //
        // You could as well use `(String, String)` to represent a label set,
        // instead of the custom type below.
        #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
        struct Labels {
            // Use your own enum types to represent label values.
            method: Method,
            // Or just a plain string.
            path: String,
        }

        #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
        enum Method {
            GET,
        }

        // Create a sample counter metric family utilizing the above custom label
        // type, representing the number of HTTP requests received.
        let http_requests = Family::<Labels, Counter>::default();

        // Register the metric family with the registry.
        registry.register(
            // With the metric name.
            "http_requests",
            // And the metric help text.
            "Number of HTTP requests received",
            http_requests.clone(),
        );

        // Somewhere in your business logic record a single HTTP GET request.
        http_requests
            .get_or_create(&Labels {
                method: Method::GET,
                path: "/metrics".to_string(),
            })
            .inc();

        let server_handle = tokio::spawn(async move {
            start_metrics_server(metrics_addr, registry).await.unwrap();
        });

        // Add a delay to ensure the server has time to start
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // send a request to the server
        let url = format!("http://{}/metrics", metrics_addr);
        println!("Fetching {}", url);
        let url = url.parse::<hyper::Uri>().unwrap();
        let resp = fetch_url(url).await.unwrap();

        // assert that the response status code is 200
        assert_eq!(resp.status(), StatusCode::OK);

        // assert that the response content type is "application/openmetrics-text; version=1.0.0; charset=utf-8"
        assert_eq!(
            resp.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
            "application/openmetrics-text; version=1.0.0; charset=utf-8"
        );

        // assert that the response body is the expected metrics
        let body = resp.collect().await.unwrap().aggregate();
        let mut body_reader = body.reader();
        let mut body_string = String::new();
        body_reader.read_to_string(&mut body_string).unwrap();

        assert_eq!(body_string, "# HELP http_requests Number of HTTP requests received.\n# TYPE http_requests counter\nhttp_requests_total{method=\"GET\",path=\"/metrics\"} 1\n# EOF\n");
        server_handle.abort();
    }
}
