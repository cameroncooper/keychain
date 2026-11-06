use std::time::Duration;

use reqwest::Certificate;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{CONNECTION, HeaderMap, HeaderValue};

use crate::Result;

const APPLE_ROOT_CA_PEM: &[u8] = include_bytes!("../../assets/apple-root-ca.pem");

/// Builds an HTTP client that trusts the normal WebPKI roots plus Apple's root CA.
///
/// Some Apple account services present a chain rooted in Apple's private root rather than a root
/// in the standard Linux/Mozilla store. The additional root is scoped to clients created for Apple
/// service requests; local anisette traffic does not use it.
pub fn apple_client(timeout: Duration) -> Result<Client> {
    Ok(apple_builder(timeout)?.build()?)
}

/// GrandSlam and escrow exchanges use independent HTTP/1.1 connections. Reusing
/// those connections can produce edge refusals between init and complete.
pub fn apple_unpooled_client(timeout: Duration) -> Result<Client> {
    Ok(apple_builder(timeout)?
        .pool_max_idle_per_host(0)
        .http1_only()
        .default_headers(HeaderMap::from_iter([(
            CONNECTION,
            HeaderValue::from_static("close"),
        )]))
        .build()?)
}

fn apple_builder(timeout: Duration) -> Result<ClientBuilder> {
    let apple_root = Certificate::from_pem(APPLE_ROOT_CA_PEM)?;
    Ok(Client::builder()
        .add_root_certificate(apple_root)
        .timeout(timeout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_apple_root_builds_a_client() {
        assert!(apple_client(Duration::from_secs(1)).is_ok());
        assert!(apple_unpooled_client(Duration::from_secs(1)).is_ok());
    }

    #[test]
    #[ignore = "requires access to Apple's authentication service"]
    fn gsa_tls_chain_is_trusted() -> Result<()> {
        let _response = apple_client(Duration::from_secs(20))?
            .get("https://gsa.apple.com/grandslam/GsService2")
            .send()?;
        Ok(())
    }
}
