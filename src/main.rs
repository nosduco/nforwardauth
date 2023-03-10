use std::net::SocketAddr;
use std::collections::BTreeMap;
use std::iter;
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper::{Method, StatusCode};
use tokio::net::TcpListener;
use std::env;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use once_cell::sync::OnceCell;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

#[derive(Debug)]
pub struct TokenSecret {
    key: Hmac<Sha256>
}

static AUTH_HEADER_NAME: &str = "X-Forward-Auth";
static LOCATION_HEADER_NAME: &str = "Location";
static INDEX_DOCUMENT: &str = "public/index.html";
static INDEX_SCRIPT: &str = "public/script.js";
static NOT_FOUND: &[u8] = b"Not Found";
static UNAUTHORIZED: &[u8] = b"Unauthorized";
static AUTHORIZED: &[u8] = b"Authorized";

static INSTANCE: OnceCell<TokenSecret> = OnceCell::new();

impl TokenSecret {
    pub fn global() -> &'static TokenSecret {
        INSTANCE.get().expect("token secret is not initialized")
    }

    fn initialize() -> Result<TokenSecret> {
        // Generate key from environment variable or randomly generated secret
        let key: Hmac<Sha256> = match env::var("TOKEN_SECRET") {
            Ok(secret) => {
                // Generate key from environment variable containing custom secret
                Hmac::new_from_slice(secret.as_bytes()).unwrap()
            },
            Err(..) => {
                // Generate random 30 character long string to act as secret
                let generated_secret: String = iter::repeat(())
                    .map(|()| thread_rng().sample(Alphanumeric))
                    .map(char::from)
                    .take(30)
                    .collect();
                // Generate key from randomly generated secret
                Hmac::new_from_slice(generated_secret.as_bytes()).unwrap()
            }
        };

        // Return token secret instance with generated key
        Ok(TokenSecret {
            key
        })
    }
}

async fn api(req: Request<hyper::body::Incoming>) -> Result<Response<BoxBody>> {
    println!("req: {:?}", req);
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/forward") => api_forward_auth(req).await,
        (&Method::POST, "/login") => api_login(req).await,
        (&Method::GET, "/login") | (&Method::GET, "/index.html") => api_serve_file(INDEX_DOCUMENT).await,
        (&Method::GET, "/script.js") => api_serve_file(INDEX_SCRIPT).await,
        _ => {
            // 404, not found
            Ok(Response::builder()
               .status(StatusCode::NOT_FOUND)
               .body(full(NOT_FOUND))
               .unwrap())
        }
    }
}

// ForwardAuth route
async fn api_forward_auth(req: Request<IncomingBody>) -> Result<Response<BoxBody>> {
    // Get token from request headers
    let headers = req.headers();
    if headers.contains_key(AUTH_HEADER_NAME) {
        let token_str = headers[AUTH_HEADER_NAME].to_str().unwrap();
        // Check if valid token exists with correct authentication key
        let claims: BTreeMap<String, String> = token_str.verify_with_key(&TokenSecret::global().key).unwrap();
        if claims["authenticated"] == "true" {
            return Ok(Response::builder()
               .status(StatusCode::OK)
               .body(full(AUTHORIZED))
               .unwrap());
        }
    }

    // No valid token found, redirect to auth backend
    Ok(Response::builder()
       .status(StatusCode::TEMPORARY_REDIRECT)
       .header(LOCATION_HEADER_NAME, "/login")
       .body(full(UNAUTHORIZED))
       .unwrap())
}

// Login route
async fn api_login(req: Request<IncomingBody>) -> Result<Response<BoxBody>> {
    // Aggregate request body
    let body = req.collect().await?.aggregate();
    // Decode JSON
    let data: serde_json::Value = serde_json::from_reader(body.reader())?;

    // Process login
    if data["username"] == "test" && data["password"] == "test" {
        // Correct login, generate claims and token
        let mut claims = BTreeMap::new();
        claims.insert("authenticated", "true");

        let token_str = claims.sign_with_key(&TokenSecret::global().key).unwrap();

        // Return OK with header to be forwarded
        Ok(Response::builder()
           .status(StatusCode::OK)
           .header(AUTH_HEADER_NAME, token_str)
           .body(full(AUTHORIZED))
           .unwrap())
    } else {
        // Incorrect login, respond with unauthorized
        Ok(Response::builder()
           .status(StatusCode::UNAUTHORIZED)
           .body(full(UNAUTHORIZED))
           .unwrap())
    }
}

// Serve file route
async fn api_serve_file(filename: &str) -> Result<Response<BoxBody>> {
    if let Ok(contents) = tokio::fs::read(filename).await {
        let body = contents.into();
        return Ok(Response::new(Full::new(body).map_err(|never| match never {}).boxed()));
    }

    // 404, not found
    Ok(Response::builder()
       .status(StatusCode::NOT_FOUND)
       .body(full(NOT_FOUND))
       .unwrap())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize token secret
    let token_secret = TokenSecret::initialize().unwrap();
    INSTANCE.set(token_secret).unwrap();

    // Create TcpListener and bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
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

// Helper function to convert full to BoxBody
fn full<T: Into<Bytes>>(chunk: T) -> BoxBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}
