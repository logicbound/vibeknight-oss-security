use std::io::{BufRead, BufReader};

use reqwest::blocking::Client;

use crate::parser::{parse_change_line, RawEvent};

const CHANGES_URL: &str = "https://replicate.npmjs.com/_changes";

/// Open a continuous connection to the npm registry change feed and iterate
/// over raw events.
///
/// Each call to `next()` returns a batch of `RawEvent`s parsed from one line
/// of the response body, along with the new `last_seq` value from that line.
///
/// The iterator blocks on I/O and is designed for use in a single-threaded
/// polling loop. On connection error the iterator terminates; the caller is
/// responsible for reconnecting with backoff.
pub struct ChangeStream {
    reader: BufReader<reqwest::blocking::Response>,
}

impl ChangeStream {
    /// Connect to the `_changes` feed starting from `since`.
    pub fn connect(client: &Client, since: &str) -> Result<Self, reqwest::Error> {
        let url = format!(
            "{}?feed=continuous&include_docs=true&since={}",
            CHANGES_URL, since
        );

        let response = client
            .get(&url)
            .timeout(std::time::Duration::from_secs(120))
            .send()?;

        Ok(Self {
            reader: BufReader::new(response),
        })
    }
}

/// One line's worth of parsed output from the feed.
pub struct StreamLine {
    /// Events extracted from this line (may be empty for heartbeats).
    pub events: Vec<RawEvent>,
    /// The raw `seq` value from the last event on this line, used to
    /// advance the state cursor. `None` for heartbeat lines.
    pub seq: Option<String>,
}

impl Iterator for ChangeStream {
    type Item = std::io::Result<StreamLine>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => None, // EOF — connection closed
            Ok(_) => {
                let events = parse_change_line(&line);
                let seq = events.first().map(|e| e.seq.clone());
                Some(Ok(StreamLine { events, seq }))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Build a blocking `reqwest` client suitable for long-lived streaming.
pub fn build_client() -> reqwest::Result<Client> {
    Client::builder()
        .use_rustls_tls()
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .build()
}
