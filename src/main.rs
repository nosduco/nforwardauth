mod config;
mod util;

use crate::config::Config;
use crate::util::{full, BoxBody, Result};
use bytes::Buf;
use cookie::time::{Duration, OffsetDateTime};
use cookie::{Cookie, SameSite};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use hyper::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper::{Method, StatusCode};
use jwt::{SignWithKey, VerifyWithKey};
use mime_guess;
use once_cell::sync::OnceCell;
use regex::Regex;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use tokio::fs;
use tokio::net::TcpListener;
use url::Url;

/* Header Names */
static FORWARDED_HOST: &str = "X-Forwarded-Host";
static FORWARDED_PROTO: &str = "X-Forwarded-Proto";
static FORWARDED_URI: &str = "X-Forwarded-Uri";

/* File Paths */
static INDEX_DOCUMENT: &str = "public/index.html";
static PASSWD_FILE: &str = "/passwd";

/* HTTP Status Responses */
static NOT_FOUND: &[u8] = b"Not Found";
static UNAUTHORIZED: &[u8] = b"Unauthorized";
static AUTHORIZED: &[u8] = b"Authorized";

/* Config Singleton Instance and Implementation */
static INSTANCE: OnceCell<Config> = OnceCell::new();
impl Config {
    pub fn global() -> &'static Config {
        INSTANCE.get().expect("config is not initialized")
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
            }
            Err(..) => {
                println!("Error: missing TOKEN_SECRET environment variable");
                std::process::exit(78);
            }
        };

        // auth_backend_url: Grab auth backend URL from environment variable
        let auth_host: String = match env::var("AUTH_HOST") {
            Ok(value) => value,
            Err(..) => {
                println!("Error: missing AUTH_HOST environment variable");
                std::process::exit(78);
            }
        };

        // cookie_secure: Whether cookie secure flag should be set
        let cookie_secure: bool = match env::var("COOKIE_SECURE") {
            Ok(secure) => secure != "false",
            Err(..) => true,
        };

        // cookie_domain: Domain cookie should be set for
        let regex = Regex::new(r"[^.]*.[^.]*$").unwrap();
        let host = regex.captures(&auth_host);
        let cookie_domain: String = match env::var("COOKIE_DOMAIN") {
            Ok(value) => value,
            Err(..) => {
                if host.is_some() {
                    host.unwrap()
                        .get(0)
                        .map_or(auth_host.clone().as_str(), |m| m.as_str())
                        .to_string()
                } else {
                    auth_host.clone()
                }
            }
        };

        // cookie_name: Name of cookie to set
        let cookie_name: String = match env::var("COOKIE_NAME") {
            Ok(value) => value,
            Err(..) => "nforwardauth".to_string(),
        };

        // Return config instance with initialized values
        Ok(Config {
            port,
            key,
            auth_host,
            cookie_secure,
            cookie_domain,
            cookie_name,
        })
    }
}

// Route table
async fn api(req: Request<hyper::body::Incoming>) -> Result<Response<BoxBody>> {
    println!("req: {:?}", req);
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/forward") => api_forward_auth(req).await,
        (&Method::POST, "/login") => api_login(req).await,
        (&Method::GET, "/login") => api_serve_file(INDEX_DOCUMENT, StatusCode::OK).await,
        _ => {
            api_serve_file(
                format!("public{}", req.uri().path()).as_str(),
                StatusCode::OK,
            )
            .await
        }
    }
}

// ForwardAuth route
async fn api_forward_auth(req: Request<IncomingBody>) -> Result<Response<BoxBody>> {
    // Get token from request headers
    let headers = req.headers();
    if headers.contains_key(COOKIE) {
        // Grab cookies from headers
        let cookies = headers[COOKIE].to_str().unwrap();
        // Find jwt cookie (if exists)
        for cookie in Cookie::split_parse(cookies) {
            let cookie = cookie.unwrap();

            if cookie.name() == Config::global().cookie_name {
                // Found cookie, parse token and validate
                let token_str = cookie.value();
                let claims: BTreeMap<String, String> =
                    token_str.verify_with_key(&Config::global().key).unwrap();
                if claims["authenticated"] == "true" {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(full(AUTHORIZED))
                        .unwrap());
                }
            }
        }
    }

    // No valid cookie/jwt found, create redirect url and return
    let mut location =
        Url::parse(format!("http://{}/login", &Config::global().auth_host).as_str())?;

    if headers.contains_key(FORWARDED_HOST)
        && headers[FORWARDED_HOST].to_str().unwrap() != &Config::global().auth_host
    {
        let mut referral_url =
            Url::parse(format!("http://{}", headers[FORWARDED_HOST].to_str().unwrap()).as_str())?;
        if headers.contains_key(FORWARDED_PROTO) {
            if let Err(_e) = referral_url.set_scheme(headers[FORWARDED_PROTO].to_str().unwrap()) {
                println!("Error setting protocol for referral url.");
            }
        }
        if headers.contains_key(FORWARDED_URI) {
            referral_url.set_path(headers[FORWARDED_URI].to_str().unwrap());
        }
        location.set_query(Some(format!("r={}", referral_url.to_string()).as_str()));
    }

    return Ok(Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(LOCATION, location.to_string())
        .body(full(UNAUTHORIZED))
        .unwrap());
}

// Login route
async fn api_login(req: Request<IncomingBody>) -> Result<Response<BoxBody>> {
    // Aggregate request body
    let body = req.collect().await?.aggregate();
    // Decode JSON
    let data: serde_json::Value = serde_json::from_reader(body.reader())?;
    // Process login and find user in passwd file
    let find_hash = get_user_hash(data["username"].as_str().unwrap()).await?;
    if find_hash.is_some() {
        // User found, verify password with hash
        let hash = find_hash.unwrap();
        let pass = data["password"].as_str().unwrap();
        let verify = pwhash::unix::verify(pass, &hash);
        if verify {
            // Correct login, generate claims and token
            let mut claims = BTreeMap::new();
            claims.insert("authenticated", "true");
            let mut now = OffsetDateTime::now_utc();
            now += Duration::days(7);
            println!("cookie domain: {}", &Config::global().cookie_domain);
            let cookie = Cookie::build(
                &Config::global().cookie_name,
                claims.sign_with_key(&Config::global().key).unwrap(),
            )
            .domain(&Config::global().cookie_domain)
            .http_only(true)
            .secure(Config::global().cookie_secure)
            .same_site(SameSite::Strict)
            .expires(now)
            .finish();

            // Return OK with cookie
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(SET_COOKIE, cookie.to_string())
                .body(full(AUTHORIZED))
                .unwrap());
        }
    }

    // Incorrect login, respond with unauthorized
    return Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(full(UNAUTHORIZED))
        .unwrap());
}

// Serve file route
async fn api_serve_file(filename: &str, status_code: StatusCode) -> Result<Response<BoxBody>> {
    if let Ok(contents) = tokio::fs::read(filename).await {
        // Get mimetype of file
        let mimetype = mime_guess::from_path(filename);
        if !mimetype.is_empty() {
            return Ok(Response::builder()
                .header(CONTENT_TYPE, mimetype.first().unwrap().to_string())
                .status(status_code)
                .body(full(contents))
                .unwrap());
        }

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

async fn get_user_hash(user: &str) -> Result<Option<String>> {
    if let Ok(passwd) = fs::read_to_string(PASSWD_FILE).await {
        let pattern = format!(r"(\n|^){}:(.+)(\n|$)", user);
        let regex = Regex::new(&pattern).unwrap();
        let user_match = regex.captures(&passwd);
        if user_match.is_some() {
            let captures = user_match.unwrap();
            return Ok(Some(captures.get(2).map_or("", |m| m.as_str()).to_string()));
        }
    }
    return Ok(None);
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize config (port, token secret, auth backend url, ...)
    let config = Config::initialize().unwrap();
    INSTANCE.set(config).unwrap();
    println!("Loaded configuration.");

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
