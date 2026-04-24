use std::time::Duration;

use reqwest::blocking::Client;

const MAX_RETRIES: u32 = 3;
const TIMEOUT_SECS: u64 = 30;
const RETRY_DELAY_SECS: u64 = 2;

#[derive(Debug)]
pub enum FetchError {
    Http(reqwest::Error),
    TooManyRetries,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Http(e) => write!(f, "HTTP error: {}", e),
            FetchError::TooManyRetries => write!(f, "Exceeded {} retries", MAX_RETRIES),
        }
    }
}

/// Download a tarball from `url` and return the raw bytes.
///
/// Retries up to `MAX_RETRIES` times with a linear delay. Each attempt has a
/// `TIMEOUT_SECS` per-connection timeout.
pub fn download_tarball(client: &Client, url: &str) -> Result<Vec<u8>, FetchError> {
    let mut last_err: Option<reqwest::Error> = None;

    for attempt in 1..=MAX_RETRIES {
        match try_download(client, url) {
            Ok(bytes) => return Ok(bytes),
            Err(e) => {
                eprintln!(
                    "[downloader] Download attempt {}/{} failed for {}: {}.",
                    attempt, MAX_RETRIES, url, e
                );
                if attempt < MAX_RETRIES {
                    std::thread::sleep(Duration::from_secs(RETRY_DELAY_SECS * u64::from(attempt)));
                }
                last_err = Some(e);
            }
        }
    }

    Err(match last_err {
        Some(e) => FetchError::Http(e),
        None    => FetchError::TooManyRetries,
    })
}

fn try_download(client: &Client, url: &str) -> Result<Vec<u8>, reqwest::Error> {
    let response = client
        .get(url)
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .send()?
        .error_for_status()?;

    Ok(response.bytes()?.to_vec())
}

/// Build a blocking `reqwest` client for tarball downloads.
pub fn build_client() -> reqwest::Result<Client> {
    Client::builder()
        .use_rustls_tls()
        .tcp_keepalive(Duration::from_secs(20))
        .build()
}
