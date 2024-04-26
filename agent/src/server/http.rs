use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{debug, info};
use prometheus_client::{encoding::text::encode, registry::Registry};
use tokio::net::TcpListener;
use tokio::pin;
use tokio::sync::broadcast::Receiver;
use tokio::task::JoinHandle;

use crate::collector::Collector;
use crate::managers::registry::RegistryManager;
use crate::progs::types::ShutdownSignal;

pub async fn serve(
    address: String,
    registry_manager: RegistryManager,
    shutdown_rx: Receiver<ShutdownSignal>,
) -> anyhow::Result<JoinHandle<()>> {
    let metrics_addr = address.parse::<SocketAddr>()?;
    let collector = Box::new(Collector::new(registry_manager));
    let mut registry = Registry::default();
    registry.register_collector(collector);
    let server_handle = tokio::spawn(async move {
        start_metrics_server(metrics_addr, registry, shutdown_rx)
            .await
            .unwrap();
    });
    Ok(server_handle)
}

/// Start an HTTP server to report metrics.
async fn start_metrics_server(
    addr: SocketAddr,
    registry: Registry,
    mut shutdown_rx: Receiver<ShutdownSignal>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(&addr).await?;
    let registry = Arc::new(registry);
    let connection_timeouts = vec![Duration::from_secs(5), Duration::from_secs(2)];

    loop {
        tokio::select! {
            Ok(signal) = shutdown_rx.recv() => {
                match signal {
                    ShutdownSignal::All => {
                    info!("Received shutdown signal, stopping server.");
                        break;
                    },
                    _ => {}
                }
            },
            accept_result = listener.accept() => {
                let (stream, _) = accept_result?;
                let io = TokioIo::new(stream);
                let registry = registry.clone();
                let connection_timeouts_clone = connection_timeouts.clone();

                tokio::task::spawn(async move {
                    let conn = http1::Builder::new().serve_connection(io, service_fn(move |req| request_handler(registry.clone(), req)));
                    pin!(conn);

                    for sleep_duration in connection_timeouts_clone {
                        tokio::select! {
                            res = conn.as_mut() => {
                                match res {
                                    Ok(()) => debug!("Connection completed without error"),
                                    Err(e) => debug!("Error serving connection: {:?}", e),
                                };
                                break;
                            }
                            _ = tokio::time::sleep(sleep_duration) => {
                                debug!("Timeout after {:?}, calling graceful_shutdown", sleep_duration);
                                conn.as_mut().graceful_shutdown();
                            }
                        }
                    }
                });
            }
        }
    }

    Ok(())
}

async fn request_handler(
    registry: Arc<Registry>,
    _request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let reg = registry.clone();
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
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr};
    use std::string::String;

    use http_body_util::BodyExt;
    use hyper::body::Buf;
    use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
    use prometheus_client::metrics::counter::Counter;
    use prometheus_client::metrics::family::Family;

    use crate::common::utils::fetch_url;

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

        let (_, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let server_handle = tokio::spawn(async move {
            start_metrics_server(metrics_addr, registry, shutdown_rx)
                .await
                .unwrap();
        });

        // Add a delay to ensure the server has time to start
        tokio::time::sleep(Duration::from_secs(1)).await;

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
