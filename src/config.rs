use hmac::{Hmac, Mac};
use once_cell::sync::OnceCell;
use regex::Regex;
use sha2::Sha256;
use std::env;

#[derive(Debug)]
pub struct Config {
    pub port: u16,
    pub auth_host: String,
    pub key: Hmac<Sha256>,
    pub cookie_secure: bool,
    pub cookie_domain: String,
    pub cookie_name: String,
}

/* Config Singleton Instance and Implementation */
static CONFIG_INSTANCE: OnceCell<Config> = OnceCell::new();
impl Config {
    pub fn global() -> &'static Config {
        CONFIG_INSTANCE.get().expect("config is not initialized")
    }

    pub fn initialize() -> Result<(), Box<dyn std::error::Error>> {
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
                    host.and_then(|h| h.get(0))
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

        // Create config instance with initialized values
        let config = Config {
            port,
            key,
            auth_host,
            cookie_secure,
            cookie_domain,
            cookie_name,
        };

        // Initialize config in instance
        CONFIG_INSTANCE.set(config).unwrap();

        // Return Ok
        Ok(())
    }
}
