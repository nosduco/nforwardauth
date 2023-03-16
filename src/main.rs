mod util;
mod config;

use std::net::SocketAddr;
use std::collections::BTreeMap;
use std::iter;
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
use cookie::{Cookie, SameSite};
use once_cell::sync::OnceCell;
use crate::util::{full, Result, BoxBody};
use crate::config::Config;
use http_body_util::BodyExt;
use bytes::Buf;
// use url::Url;



/* Header Names */
static FORWARD_HOST_HEADER: &str = "X-Forwarded-Host";
static FORWARD_AUTH_HEADER: &str = "X-Forwarded-Auth";
static FORWARD_USER_HEADER: &str = "X-Forwarded-User";
static LOCATION_HEADER: &str = "Location";

/* Static Fiiles */
static INDEX_DOCUMENT: &str = "public/index.html";
static INDEX_SCRIPT: &str = "public/script.js";

/* HTTP Status Responses */
static NOT_FOUND: &[u8] = b"Not Found";
static UNAUTHORIZED: &[u8] = b"Unauthorized";
static AUTHORIZED: &[u8] = b"Authorized";

/* Config Singleton Instance */
static INSTANCE: OnceCell<Config> = OnceCell::new();

impl Config {
    pub fn global() -> &'static Config {
        INSTANCE.get().expect("token secret is not initialized")
    }

    fn initialize() -> Result<Config> {
        // port: Port server should bind and listen on
        let port: u16 = match env::var("PORT") {
            Ok(port) => port.parse::<u16>().unwrap(),
            Err(..) => 3000,
        };

        // key: Generate key from environment variable or randomly generated secret
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

        // auth_backend_url: Grab auth backend URL from environment variable
        let auth_backend_url: String = match env::var("AUTH_BACKEND_URL") {
            Ok(value) => value,
            Err(..) => {
                println!("Error: missing AUTH_BACKEND_URL environment variable");
                std::process::exit(78);
            }
        };

        // Return config instance with initialized values
        Ok(Config {
            port,
            key,
            auth_backend_url
        })
    }
}

// Route table
async fn api(req: Request<hyper::body::Incoming>) -> Result<Response<BoxBody>> {
    println!("req: {:?}", req);
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/forward") => api_forward_auth(req).await,
        (&Method::POST, "/login") => api_login(req).await,
        (&Method::GET, "/login") | (&Method::GET, "/index.html") => api_serve_file(INDEX_DOCUMENT, StatusCode::OK).await,
        (&Method::GET, "/script.js") => api_serve_file(INDEX_SCRIPT, StatusCode::OK).await,
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
    if headers.contains_key(hyper::header::COOKIE) {
        // Grab cookies from headers
        let cookies = headers[hyper::header::COOKIE].to_str().unwrap();

        // Find jwt cookie (if exists)
        for cookie in Cookie::split_parse(cookies) {
            let cookie = cookie.unwrap();

            if cookie.name() == "simple-forward-auth-jwt" {
                // Found cookie, parse token and validate
                let token_str = cookie.value();
                let claims: BTreeMap<String, String> = token_str.verify_with_key(&Config::global().key).unwrap();
                if claims["authenticated"] == "true" {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(full(AUTHORIZED))
                        .unwrap());
                }
            }
        }
    }

    // No valid cookie/jwt found, redirect to login page
    return Ok(Response::builder().status(StatusCode::TEMPORARY_REDIRECT)
              .header(LOCATION_HEADER, format!("http://{}/login", &Config::global().auth_backend_url))
              .body(full(UNAUTHORIZED))
              .unwrap());
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
        let cookie = Cookie::build("simple-forward-auth-jwt", claims.sign_with_key(&Config::global().key).unwrap())
            .domain("localhost.com")
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Strict)
            .finish();

        // Return OK with cookie
        Ok(Response::builder()
           .status(StatusCode::OK)
           .header(hyper::header::SET_COOKIE, cookie.to_string())
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
async fn api_serve_file(filename: &str, status_code: StatusCode) -> Result<Response<BoxBody>> {
    if let Ok(contents) = tokio::fs::read(filename).await {
        return Ok(Response::builder()
           .status(status_code)
           .body(full(contents))
           .unwrap());
    }

    // 404, not found
    Ok(Response::builder()
       .status(StatusCode::NOT_FOUND)
       .body(full(NOT_FOUND))
       .unwrap())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize config (port, token secret, auth backend url, ...)
    let config = Config::initialize().unwrap();
    INSTANCE.set(config).unwrap();

    // Create TcpListener and bind
    let addr = SocketAddr::from(([0, 0, 0, 0], Config::global().port));
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
