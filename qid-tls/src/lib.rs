//! TLS protocol primitives owned by qid. Handshake helpers are offline byte
//! computations; this crate does not run a listener or TLS server.

pub mod tls12;
pub mod tls13;
