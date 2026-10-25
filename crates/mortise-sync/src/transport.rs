//! How requests reach the relay.
//!
//! Behind a trait for one reason: it makes the sync logic testable without a
//! server, and testable against a server that misbehaves in ways a real one
//! rarely does on demand.

use crate::error::{Error, Result};

/// One HTTP round trip.
pub trait Transport: Send + Sync {
    /// Send a request and return the status and body.
    ///
    /// A transport error means "could not reach the relay"; an HTTP status is
    /// returned as data, because a 401 is a fact about the request, not a
    /// failure to make it.
    fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>)>;
}

/// Talks to a real relay over HTTP.
pub struct HttpTransport {
    base_url: String,
    agent: ureq::Agent,
}

impl HttpTransport {
    /// Point a transport at a relay.
    ///
    /// A trailing slash on `base_url` would produce `//v1/...` paths that no
    /// longer match what was signed, so it is trimmed here rather than left to
    /// every caller.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            agent: ureq::Agent::new_with_defaults(),
        }
    }

    /// The relay this transport targets.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Transport for HttpTransport {
    fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>)> {
        let url = format!("{}{}", self.base_url, path);

        // ureq 3 types its builder by whether a body follows, so the two
        // methods cannot share one variable. Both calls land on the same
        // Result type, which is what the match below needs.
        let result = match method {
            "GET" => {
                let mut request = self.agent.get(&url);
                for (name, value) in headers {
                    request = request.header(*name, value);
                }
                request.call()
            }
            "POST" => {
                let mut request = self.agent.post(&url);
                for (name, value) in headers {
                    request = request.header(*name, value);
                }
                request
                    .header("content-type", "application/json")
                    .send(body)
            }
            "DELETE" => {
                let mut request = self.agent.delete(&url);
                for (name, value) in headers {
                    request = request.header(*name, value);
                }
                request.call()
            }
            other => {
                return Err(Error::Unreachable(format!("unsupported method {other}")));
            }
        };

        // ureq treats a non-2xx as an error. The status is still the thing the
        // caller needs — a 401 is a fact about the request, not a failure to
        // make it — so unwrap it back out.
        let mut response = match result {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(code)) => return Ok((code, Vec::new())),
            Err(e) => return Err(Error::Unreachable(e.to_string())),
        };

        let status = response.status().as_u16();
        let bytes = response
            .body_mut()
            .read_to_vec()
            .map_err(|e| Error::Unreachable(e.to_string()))?;
        Ok((status, bytes))
    }
}
