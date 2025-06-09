mod config;
mod middleware;
mod util;

use crate::config::Config;
use crate::util::{full, BoxBody, Result};
use bytes::Buf;
use cookie::time::{Duration as CookieDuration, OffsetDateTime};
use cookie::{Cookie, SameSite};
use http_auth_basic::Credentials;
use http_body_util::BodyExt;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use jwt::{SignWithKey, VerifyWithKey};
use regex::Regex;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::fs;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use url::Url;

/* Header Names */
static FORWARDED_HOST: &str = "X-Forwarded-Host";
static FORWARDED_PROTO: &str = "X-Forwarded-Proto";
static FORWARDED_URI: &str = "X-Forwarded-Uri";
static FORWARDED_FOR: &str = "X-Forwarded-For";

/* File Paths */
static INDEX_DOCUMENT: &str = "/public/index.html";
static LOGOUT_DOCUMENT: &str = "/public/logout.html";
static PASSWD_FILE: &str = "/passwd";

/* HTTP Status Responses */
static NOT_FOUND: &[u8] = b"Not Found";
static UNAUTHORIZED: &[u8] = b"Unauthorized";
static AUTHORIZED: &[u8] = b"Authorized";
static LOGGED_OUT: &[u8] = b"Logged Out";
static TOO_MANY_REQUESTS: &[u8] = b"Too Many Requests";

// Route table
async fn api(req: Request<hyper::body::Incoming>) -> Result<Response<BoxBody>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/forward") => api_forward_auth(req, None).await,
        (&Method::GET, "/nginx") => api_forward_auth(req, Some(StatusCode::UNAUTHORIZED)).await,
        (&Method::POST, "/login") => api_login(req).await,
        (&Method::GET, "/login") => api_login_wrapper(req).await,
        (&Method::POST, "/logout") => api_logout().await,
        (&Method::GET, "/logout") => api_serve_file(LOGOUT_DOCUMENT, StatusCode::OK).await,
        _ => {
            api_serve_file(
                format!("/public{}", req.uri().path()).as_str(),
                StatusCode::OK,
            )
            .await
        }
    }
}

// ForwardAuth route
async fn api_forward_auth(
    req: Request<IncomingBody>,
    reject_status_code: Option<StatusCode>,
) -> Result<Response<BoxBody>> {
    // Get token from request headers and check if cookie exists
    let headers = req.headers();
// check validity of FORWARDED_HOST
    let forwarded_host = headers
    .get(FORWARDED_HOST)
    .and_then(|v| v.to_str().ok());
    // check if traffic is forwarded
    let is_forwarded = forwarded_host
    .map(|host| host != Config::global().auth_host)
    .unwrap_or(false);

    if headers.contains_key(COOKIE) {
        // Grab cookies from headers
        let cookies = headers[COOKIE].to_str().unwrap();
        // Find jwt cookie (if exists)
        for cookie in Cookie::split_parse(cookies) {
            let cookie = cookie.unwrap();

            if cookie.name() == Config::global().cookie_name {
                // Found cookie, parse token and validate
                let token_str = cookie.value();
                let result: core::result::Result<BTreeMap<String, String>, _> =
                    token_str.verify_with_key(&Config::global().key);
                if let Ok(claims) = result {
                    if claims["authenticated"] == "true" {
                        let username = claims.get("user").cloned().unwrap_or_default();
                        if is_forwarded { //Set X-Forwarded-User on forwarded request, dont send Logout page on forward
                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header("X-Forwarded-User", username)
                                .body(full(AUTHORIZED))
                                .unwrap());
                        } else {
                        return api_serve_file(LOGOUT_DOCUMENT, StatusCode::OK).await;
                        }
                    }
                }
            }
        }
    }

    // Check if basic auth exists
    if headers.contains_key(AUTHORIZATION) {
        // Grab basic auth header and parse credentials
        let basic_auth = headers[AUTHORIZATION].to_str().unwrap();
        let credentials = Credentials::from_header(basic_auth.to_string()).unwrap();

        // Check login against passwd file
        let find_hash = get_user_hash(&credentials.user_id).await?;
        if let Some(hash) = find_hash {
            // User found, verify password with hash
            let verify = pwhash::unix::verify(&credentials.password, &hash);
            if verify {
                // Correct login
                return api_serve_file(LOGOUT_DOCUMENT, StatusCode::OK).await;
            }
        }
    }

    // No valid cookie/jwt found, create redirect url and return
    let mut location =
        Url::parse(format!("http://{}/login", &Config::global().auth_host).as_str())?;

    // Set redirection location protocol based on X-Forwarded-Proto
    if headers.contains_key(FORWARDED_PROTO) {
        if let Err(_e) = location.set_scheme(headers[FORWARDED_PROTO].to_str().unwrap()) {
            println!("Error: Failed setting protocol for redirect location.");
        }
    }
// Set redirection URI for redirection on login
    if is_forwarded {
        let mut referral_url =
            Url::parse(format!("http://{}", headers[FORWARDED_HOST].to_str().unwrap()).as_str())?;
        // Set referral protocol based on X-Forwarded-Proto
        if headers.contains_key(FORWARDED_PROTO) {
            if let Err(_e) = referral_url.set_scheme(headers[FORWARDED_PROTO].to_str().unwrap()) {
                println!("Error: Failed setting protocol for referral url.");
            }
        }
        if headers.contains_key(FORWARDED_URI) {
            referral_url.set_path(headers[FORWARDED_URI].to_str().unwrap());
        }
        location.set_query(Some(format!("r={}", referral_url).as_str()));
    }

    let res_status_code = reject_status_code.unwrap_or(StatusCode::TEMPORARY_REDIRECT);
    Ok(Response::builder()
        .status(res_status_code)
        .header(LOCATION, location.to_string())
        .body(full(UNAUTHORIZED))
        .unwrap())
}

// Login route
async fn api_login(req: Request<IncomingBody>) -> Result<Response<BoxBody>> {
    // Get headers from request
    let headers = req.headers();
    // Middleware - rate limiter
    if let Some(mut rate_limiter) = middleware::RateLimiter::global() {
        // Rate limiter is enabled, grab IP from header and check rate limit
        if headers.contains_key(FORWARDED_FOR) {
            let x_forwarded_for = headers[FORWARDED_FOR].to_str().unwrap();
            let source_ip = x_forwarded_for.split(',').next().unwrap_or(x_forwarded_for);
            if let Ok(ip) = source_ip.trim().parse::<IpAddr>() {
                if !rate_limiter.try_login(ip) {
                    // Rate limit exceeded, return an error response
                    return Ok(Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .body(full(TOO_MANY_REQUESTS))
                        .unwrap());
                }
            } else {
                println!(
                    "Warning: Failed to parse {} header from request.",
                    FORWARDED_FOR
                );
            }
        } else {
            println!(
                "Warning: Request without {} header processed.",
                FORWARDED_FOR
            );
        }
    }
    // Aggregate request body
    let body = req.collect().await?.aggregate();
    // Decode JSON
    let data: serde_json::Value = serde_json::from_reader(body.reader())?;
    // Process login and find user in passwd file
    let user = data["username"].as_str().unwrap();
    let find_hash = get_user_hash(user).await?;
    if let Some(hash) = find_hash {
        // User found, verify password with hash
        let pass = data["password"].as_str().unwrap();
        let verify = pwhash::unix::verify(pass, &hash);
        if verify {
            // Correct login, generate claims and token
            let mut claims = BTreeMap::new();
            claims.insert("authenticated", "true");
            claims.insert("user", user);
            let mut now = OffsetDateTime::now_utc();
            now += CookieDuration::days(7);
            let cookie = Cookie::build(
                &Config::global().cookie_name,
                claims.sign_with_key(&Config::global().key).unwrap(),
            )
            .domain(&Config::global().cookie_domain)
            .http_only(true)
            .secure(Config::global().cookie_secure)
            .same_site(SameSite::Lax)
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
    Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(full(UNAUTHORIZED))
        .unwrap())
}

// Login serve file wrapper
async fn api_login_wrapper(req: Request<IncomingBody>) -> Result<Response<BoxBody>> {
    // Get token from request headers and check if cookie exists, otherwise serve login page
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
                let result: core::result::Result<BTreeMap<String, String>, _> =
                    token_str.verify_with_key(&Config::global().key);

                if let Ok(claims) = result {
                    if claims["authenticated"] == "true" {
                        // Fetch the 'r' query parameter from the request
                        let target_url = req
                            .uri()
                            .query()
                            .and_then(|query| {
                                query
                                    .split('&')
                                    .find(|pair| pair.starts_with("r="))
                                    .and_then(|pair| pair.strip_prefix("r="))
                            })
                            .map(|s| s.to_string());

                        if let Some(target_url) = target_url {
                            // Target URL exists, redirect, no X-Forwarded-User header needed, as forwarded request is coming -after- redirect
                            return Ok(Response::builder()
                                .status(StatusCode::TEMPORARY_REDIRECT)
                                .header(LOCATION, target_url)
                                .body(full(AUTHORIZED))
                                .unwrap());
                        } else {
                            // Serve logout page
                            return api_forward_auth(req, None).await;
                        }
                    }
                }
            }
        }
    }

    api_serve_file(INDEX_DOCUMENT, StatusCode::OK).await
}

// Logout route
async fn api_logout() -> Result<Response<BoxBody>> {
    // Build cookie in past to expire existing cookies in browser
    let past = OffsetDateTime::now_utc() - CookieDuration::days(1);
    let expired_cookie = Cookie::build(&Config::global().cookie_name, "")
        .domain(&Config::global().cookie_domain)
        .http_only(true)
        .secure(Config::global().cookie_secure)
        .same_site(SameSite::Lax)
        .expires(past)
        .finish();

    // Return OK with cookie
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(SET_COOKIE, expired_cookie.to_string())
        .body(full(LOGGED_OUT))
        .unwrap())
}

fn is_safe_path(path: &str) -> bool {
    // Normalize path by removing duplicate slashes
    let normalized = path
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    // Special cases for known good files
    if path == INDEX_DOCUMENT || path == LOGOUT_DOCUMENT {
        return true;
    }

    // All other paths must start with /public and not contain ..
    normalized.first() == Some(&"public") && !normalized.contains(&"..")
}

// Serve file route
async fn api_serve_file(filename: &str, status_code: StatusCode) -> Result<Response<BoxBody>> {
    if !is_safe_path(filename) {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full(NOT_FOUND))
            .unwrap());
    }

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
        if let Some(captures) = user_match {
            return Ok(Some(captures.get(2).map_or("", |m| m.as_str()).to_string()));
        }
    }
    Ok(None)
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize config (port, token secret, auth backend url, ...)
    Config::initialize()?;
    println!("Loaded configuration.");

    // Initialize rate limiter (if enabled)
    if Config::global().rate_limiter_enabled {
        middleware::RateLimiter::initialize(
            Config::global().rate_limiter_max_retries,
            Duration::from_secs(Config::global().rate_limiter_find_time.into()),
            Duration::from_secs(Config::global().rate_limiter_ban_time.into()),
        );
    }

    // Setup signal handling
    let mut term_signal = signal(SignalKind::terminate())?;
    let mut int_signal = signal(SignalKind::interrupt())?;

    // Create TcpListener and bind
    let addr = SocketAddr::from(([0, 0, 0, 0], Config::global().port));
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);

    // Create a future to handle server startup
    let server = async {
        // Start loop to continuously accept incoming connections
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let io = TokioIo::new(stream);

                    // Spawn a tokio task to serve multiple connections concurrently
                    tokio::task::spawn(async move {
                        // Finally, bind the incoming connection to our index service
                        if let Err(err) = http1::Builder::new()
                            // Convert function to service
                            .serve_connection(io, service_fn(api))
                            .await
                        {
                            println!("Error: Failed serving connection: {:?}", err);
                        }
                    });
                }
                Err(e) => {
                    println!("Error accepting connection: {:?}", e);
                    continue;
                }
            };
        }
    };

    // Create a future to handle signals
    let shutdown_signal = async {
        tokio::select! {
            _ = term_signal.recv() => {},
            _ = int_signal.recv() => {},
        }
    };

    // Run server with signal handling
    tokio::select! {
        _ = server => {},
        _ = shutdown_signal => {
            println!("Shutdown signal received, shutting down...")
        },
    }
    Ok(())
}
