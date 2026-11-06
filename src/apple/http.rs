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

/// Writes must never follow a redirect or be replayed by the HTTP client's
/// protocol retry machinery. Recovery belongs to the durable upload journal.
pub fn apple_write_client(timeout: Duration) -> Result<Client> {
    Ok(apple_builder(timeout)?
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()?)
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
    use std::io::{BufRead, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Instant;

    fn accept_until(
        listener: &TcpListener,
        deadline: Instant,
    ) -> std::io::Result<Option<TcpStream>> {
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => return Ok(Some(stream)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }
    fn read_request(stream: &mut TcpStream) -> std::io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut reader = std::io::BufReader::new(stream);
        let mut size = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                size = value
                    .trim()
                    .parse()
                    .map_err(|_| std::io::ErrorKind::InvalidData)?;
            }
        }
        if size > 1024 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        reader.read_exact(&mut vec![0u8; size])
    }

    #[test]
    fn write_client_does_not_follow_a_redirect_with_account_headers() -> crate::Result<()> {
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|e| crate::Error::io("test listener", e))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| crate::Error::io("test listener", e))?;
        let target =
            TcpListener::bind("127.0.0.1:0").map_err(|e| crate::Error::io("test target", e))?;
        target
            .set_nonblocking(true)
            .map_err(|e| crate::Error::io("test target", e))?;
        let destination = target
            .local_addr()
            .map_err(|e| crate::Error::io("test target", e))?;
        let url = format!(
            "http://{}/save",
            listener
                .local_addr()
                .map_err(|e| crate::Error::io("test listener", e))?
        );
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let mut stream = accept_until(&listener, Instant::now() + Duration::from_secs(3))?
                .ok_or(std::io::ErrorKind::TimedOut)?;
            read_request(&mut stream)?;
            write!(
                stream,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{destination}/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )?;
            Ok(())
        });
        let response = apple_write_client(Duration::from_secs(2))?
            .post(url)
            .header("x-cloudkit-authtoken", "synthetic-only")
            .body("synthetic body")
            .send()?;
        assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        server
            .join()
            .unwrap_or_else(|_| panic!("test server thread"))
            .map_err(|e| crate::Error::io("test server", e))?;
        assert!(matches!(target.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
        Ok(())
    }

    #[test]
    fn write_client_does_not_resend_after_a_lost_response() -> crate::Result<()> {
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|e| crate::Error::io("test listener", e))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| crate::Error::io("test listener", e))?;
        let url = format!(
            "http://{}/save",
            listener
                .local_addr()
                .map_err(|e| crate::Error::io("test listener", e))?
        );
        let server = std::thread::spawn(move || -> std::io::Result<usize> {
            let mut stream = accept_until(&listener, Instant::now() + Duration::from_secs(3))?
                .ok_or(std::io::ErrorKind::TimedOut)?;
            read_request(&mut stream)?;
            drop(stream); // The write may have committed; deliberately lose its reply.
            let mut attempts = 1;
            let deadline = Instant::now() + Duration::from_millis(300);
            while let Some(mut stream) = accept_until(&listener, deadline)? {
                attempts += 1;
                read_request(&mut stream)?;
            }
            Ok(attempts)
        });
        assert!(
            apple_write_client(Duration::from_secs(2))?
                .post(url)
                .body("synthetic body")
                .send()
                .is_err()
        );
        assert_eq!(
            server
                .join()
                .unwrap_or_else(|_| panic!("test server thread"))
                .map_err(|e| crate::Error::io("test server", e))?,
            1
        );
        Ok(())
    }

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
