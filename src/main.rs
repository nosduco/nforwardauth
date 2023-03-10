use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper::{Method, Result, StatusCode};
use tokio::net::TcpListener;

static INDEX_DOCUMENT: &str = "public/index.html";
static INDEX_SCRIPT: &str = "public/script.js";
static NOTFOUND: &[u8] = b"Not Found";

async fn api(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/index.html") => serve_file(INDEX_DOCUMENT).await,
        (&Method::GET, "/script.js") => serve_file(INDEX_SCRIPT).await,
        (&Method::POST, "/login") => api_login(req).await,
        _ => Ok(not_found()),
    }
}

// Login route
async fn api_post_request(req: Request<IncomingBody>) -> Result<Response<BoxBody>> {
}

// Serve file route
async fn serve_file(filename: &str) -> Result<Response<Full<Bytes>>> {
    if let Ok(contents) = tokio::fs::read(filename).await {
        let body = contents.into();
        return Ok(Response::new(Full::new(body)));
    }

    Ok(not_found())
}

// 404 route
fn not_found() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(NOTFOUND.into()))
        .unwrap()
}


#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // Create TcpListener and bind to 127.0.0.1:3000
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);

    // Start loop to continuously accept incoming connections
    loop {
        let (stream, _) = listener.accept().await?;

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, bind the incoming connection to our index service
            if let Err(err) = http1::Builder::new()
                // Convert function to service
                .serve_connection(stream, service_fn(api))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
