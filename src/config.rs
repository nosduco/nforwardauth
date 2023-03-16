use sha2::Sha256;
use hmac::Hmac;

#[derive(Debug)]
pub struct Config {
    pub port: u16,
    pub auth_backend_url: String,
    pub key: Hmac<Sha256>,
}
