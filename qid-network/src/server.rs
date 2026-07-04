//! Async network-AAA server runtime.
//!
//! Provides Tokio-based UDP and TCP listeners for RADIUS and TACACS+
//! respectively. The runtime reuses the wire-format helpers in
//! `qid_network` for parsing and constructing protocol messages; it
//! is intentionally a thin shim so adapters can plug in custom
//! authentication backends without depending on the protocol crates.
//!
//! ## RADIUS server components
//!
//! * **Authentication** — `run_radius_server` listens for Access-Request
//!   packets and responds with Access-Accept/Reject.
//! * **Accounting** — `run_radius_accounting_server` listens for
//!   Accounting-Request (code 4) packets and responds with
//!   Accounting-Response (code 5) after packet authenticator validation.
//! * **CoA** — `run_radius_coa_server` listens for CoA-Request / Disconnect-
//!   Request (RFC 5176), validates the authenticator, and returns the matching
//!   ACK response code.

use qid_core::error::{QidError, QidResult};
use std::sync::Arc;

use crate::{
    EapCode, RadiusAttribute, RadiusCode, RadiusPacket, parse_radius_packet,
    radius_response_authenticator, verify_radius_message_authenticator,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadiusAccessDecision {
    Accept {
        reply_message: String,
        session_timeout_seconds: Option<u32>,
    },
    Reject {
        reply_message: String,
    },
}

pub type RadiusAccessAuthorizer =
    Arc<dyn Fn(&str, &RadiusPacket<'_>) -> RadiusAccessDecision + Send + Sync + 'static>;

/// Handle a single RADIUS access-request packet. The handler
/// validates the request authenticator, looks up the shared secret
/// for the source peer, computes a deterministic access-accept or
/// access-reject response, and signs the response authenticator.
pub async fn handle_radius_access_request(
    socket: &tokio::net::UdpSocket,
    peer: std::net::SocketAddr,
    request_bytes: Vec<u8>,
    shared_secret: &[u8],
) -> QidResult<()> {
    let encoded = handle_radius_access_request_bytes(&request_bytes, shared_secret)?;
    socket
        .send_to(&encoded, peer)
        .await
        .map_err(|e| QidError::Internal {
            message: format!("RADIUS send_to failed: {e}"),
        })?;
    Ok(())
}

pub async fn handle_radius_access_request_with_authorizer(
    socket: &tokio::net::UdpSocket,
    peer: std::net::SocketAddr,
    request_bytes: Vec<u8>,
    shared_secret: &[u8],
    authorizer: &(dyn Fn(&str, &RadiusPacket<'_>) -> RadiusAccessDecision + Send + Sync),
) -> QidResult<()> {
    let encoded = handle_radius_access_request_bytes_with_authorizer(
        &request_bytes,
        shared_secret,
        authorizer,
    )?;
    socket
        .send_to(&encoded, peer)
        .await
        .map_err(|e| QidError::Internal {
            message: format!("RADIUS send_to failed: {e}"),
        })?;
    Ok(())
}

/// Validate and answer a single RADIUS Access-Request packet.
pub fn handle_radius_access_request_bytes(
    request_bytes: &[u8],
    shared_secret: &[u8],
) -> QidResult<Vec<u8>> {
    handle_radius_access_request_bytes_with_authorizer(request_bytes, shared_secret, &|_, _| {
        RadiusAccessDecision::Reject {
            reply_message: "RADIUS access policy is not configured".to_string(),
        }
    })
}

pub fn handle_radius_access_request_bytes_with_authorizer(
    request_bytes: &[u8],
    shared_secret: &[u8],
    authorizer: &(dyn Fn(&str, &RadiusPacket<'_>) -> RadiusAccessDecision + Send + Sync),
) -> QidResult<Vec<u8>> {
    let request = parse_radius_packet(request_bytes)?;
    if !crate::verify_radius_request_authenticator(shared_secret, &request, request_bytes) {
        return Err(QidError::Unauthorized {
            message: "RADIUS request authenticator mismatch".to_string(),
        });
    }
    // Verify Message-Authenticator (RFC 3579 §3.2 / RFC 7361) if present
    let message_authenticator_offset = find_message_authenticator_offset(request_bytes);
    if let Some(offset) = message_authenticator_offset {
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&request_bytes[offset..offset + 32]);
        if !verify_radius_message_authenticator(shared_secret, request_bytes, offset, &expected)? {
            return Err(QidError::Unauthorized {
                message: "RADIUS Message-Authenticator mismatch".to_string(),
            });
        }
    }
    let user_name = request
        .attributes
        .iter()
        .find(|attr| attr.kind == attrs::USER_NAME)
        .and_then(|attr| std::str::from_utf8(attr.value).ok())
        .unwrap_or("")
        .to_string();
    let (code, attributes) = decide_radius_response(&user_name, &request, authorizer);
    Ok(encode_radius_response(
        request.identifier,
        &request.authenticator,
        code,
        attributes,
        shared_secret,
    ))
}

/// Handle a single RADIUS Accounting-Request packet (code 4).
/// Validates the request authenticator, logs the accounting data,
/// and responds with Accounting-Response (code 5).
pub async fn handle_radius_accounting_request(
    socket: &tokio::net::UdpSocket,
    peer: std::net::SocketAddr,
    request_bytes: Vec<u8>,
    shared_secret: &[u8],
) -> QidResult<()> {
    let request = parse_radius_packet(&request_bytes)?;
    if request.code != RadiusCode::AccountingRequest {
        return Err(QidError::BadRequest {
            message: "not an Accounting-Request packet".to_string(),
        });
    }
    if !crate::verify_radius_request_authenticator(shared_secret, &request, &request_bytes) {
        return Err(QidError::Unauthorized {
            message: "RADIUS accounting request authenticator mismatch".to_string(),
        });
    }
    // Verify Message-Authenticator if present
    let message_authenticator_offset = find_message_authenticator_offset(&request_bytes);
    if let Some(offset) = message_authenticator_offset {
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&request_bytes[offset..offset + 32]);
        if !verify_radius_message_authenticator(shared_secret, &request_bytes, offset, &expected)? {
            return Err(QidError::Unauthorized {
                message: "RADIUS accounting Message-Authenticator mismatch".to_string(),
            });
        }
    }
    // Build Accounting-Response
    let encoded = encode_radius_response(
        request.identifier,
        &request.authenticator,
        RadiusCode::AccountingResponse,
        Vec::new(),
        shared_secret,
    );
    socket
        .send_to(&encoded, peer)
        .await
        .map_err(|e| QidError::Internal {
            message: format!("RADIUS accounting send_to failed: {e}"),
        })?;
    Ok(())
}

/// Handle a single RADIUS CoA-Request / Disconnect-Request packet
/// (RFC 5176). Validates the authenticator and returns CoA-ACK /
/// Disconnect-ACK for accepted requests.
pub async fn handle_radius_coa_request(
    socket: &tokio::net::UdpSocket,
    peer: std::net::SocketAddr,
    request_bytes: Vec<u8>,
    shared_secret: &[u8],
) -> QidResult<()> {
    let request = parse_radius_packet(&request_bytes)?;
    if request.code != RadiusCode::CoARequest && request.code != RadiusCode::DisconnectRequest {
        return Err(QidError::BadRequest {
            message: "not a CoA/Disconnect-Request packet".to_string(),
        });
    }
    if !crate::verify_radius_request_authenticator(shared_secret, &request, &request_bytes) {
        return Err(QidError::Unauthorized {
            message: "RADIUS CoA request authenticator mismatch".to_string(),
        });
    }
    let response_code = match request.code {
        RadiusCode::CoARequest => RadiusCode::CoAACK,
        _ => RadiusCode::DisconnectACK,
    };
    let encoded = encode_radius_response(
        request.identifier,
        &request.authenticator,
        response_code,
        Vec::new(),
        shared_secret,
    );
    socket
        .send_to(&encoded, peer)
        .await
        .map_err(|e| QidError::Internal {
            message: format!("RADIUS CoA send_to failed: {e}"),
        })?;
    Ok(())
}

fn decide_radius_response(
    user_name: &str,
    request: &RadiusPacket,
    authorizer: &(dyn Fn(&str, &RadiusPacket<'_>) -> RadiusAccessDecision + Send + Sync),
) -> (RadiusCode, Vec<RadiusAttribute<'static>>) {
    if user_name.is_empty() {
        return (
            RadiusCode::AccessReject,
            vec![RadiusAttribute {
                kind: attrs::REPLY_MESSAGE,
                value: Box::leak(b"missing user-name".to_vec().into_boxed_slice()),
            }],
        );
    }
    match authorizer(user_name, request) {
        RadiusAccessDecision::Accept {
            reply_message,
            session_timeout_seconds,
        } => {
            let mut attributes: Vec<RadiusAttribute<'static>> = Vec::new();
            if let Some(timeout) = session_timeout_seconds {
                attributes.push(RadiusAttribute {
                    kind: attrs::SESSION_TIMEOUT,
                    value: Box::leak(timeout.to_string().into_bytes().into_boxed_slice()),
                });
            }
            attributes.push(RadiusAttribute {
                kind: attrs::REPLY_MESSAGE,
                value: Box::leak(reply_message.into_bytes().into_boxed_slice()),
            });
            for attr in &request.attributes {
                if attr.kind == attrs::EAP_MESSAGE {
                    let identifier = attr.value.get(1).copied().unwrap_or(0);
                    let eap: &'static [u8] = Box::leak(
                        vec![EapCode::Success.as_byte(), identifier, 0, 4].into_boxed_slice(),
                    );
                    attributes.push(RadiusAttribute {
                        kind: attrs::EAP_MESSAGE,
                        value: eap,
                    });
                }
            }
            (RadiusCode::AccessAccept, attributes)
        }
        RadiusAccessDecision::Reject { reply_message } => (
            RadiusCode::AccessReject,
            vec![RadiusAttribute {
                kind: attrs::REPLY_MESSAGE,
                value: Box::leak(reply_message.into_bytes().into_boxed_slice()),
            }],
        ),
    }
}

fn encode_radius_packet_with_code(
    packet: &RadiusPacket<'_>,
    code: RadiusCode,
    attributes: Vec<RadiusAttribute<'static>>,
) -> Vec<u8> {
    let body_len: usize = attributes.iter().map(|attr| attr.value.len() + 2).sum();
    let total_len = 20 + body_len;
    let mut buf = Vec::with_capacity(total_len);
    buf.push(code.as_byte());
    buf.push(packet.identifier);
    buf.extend_from_slice(&(total_len as u16).to_be_bytes());
    buf.extend_from_slice(&packet.authenticator);
    for attr in &attributes {
        buf.push(attr.kind);
        buf.push((attr.value.len() + 2) as u8);
        buf.extend_from_slice(attr.value);
    }
    buf
}

/// Encode a Radius response packet with computed authenticator. The
/// caller supplies the request authenticator so the response
/// authenticator can be derived with `radius_response_authenticator`.
pub fn encode_radius_response(
    identifier: u8,
    request_authenticator: &[u8; 16],
    code: RadiusCode,
    attributes: Vec<RadiusAttribute<'static>>,
    shared_secret: &[u8],
) -> Vec<u8> {
    let mut buf = encode_radius_packet_with_code(
        &RadiusPacket {
            code,
            identifier,
            authenticator: [0u8; 16],
            attributes: Vec::new(),
        },
        code,
        attributes,
    );
    let authenticator =
        radius_response_authenticator(shared_secret, request_authenticator, &buf[4..]);
    buf[4..20].copy_from_slice(&authenticator);
    buf
}

/// Find the byte offset of the Message-Authenticator attribute value
/// inside a raw RADIUS packet. Returns `None` if no Message-Authenticator
/// is present.
fn find_message_authenticator_offset(packet: &[u8]) -> Option<usize> {
    if packet.len() < 20 {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if packet.len() < total_len {
        return None;
    }
    let mut pos = 20;
    while pos + 1 < total_len {
        let attr_type = packet[pos];
        let attr_len = packet[pos + 1] as usize;
        if attr_len < 2 {
            break;
        }
        if attr_type == 80 && attr_len == 34 {
            return Some(pos + 2);
        }
        pos += attr_len;
    }
    None
}

pub mod attrs {
    pub const USER_NAME: u8 = 1;
    pub const USER_PASSWORD: u8 = 2;
    pub const CHAP_PASSWORD: u8 = 3;
    pub const NAS_IP_ADDRESS: u8 = 4;
    pub const NAS_PORT: u8 = 5;
    pub const SERVICE_TYPE: u8 = 6;
    pub const REPLY_MESSAGE: u8 = 18;
    pub const STATE: u8 = 24;
    pub const VENDOR_SPECIFIC: u8 = 26;
    pub const SESSION_TIMEOUT: u8 = 27;
    pub const CALLED_STATION_ID: u8 = 30;
    pub const CALLING_STATION_ID: u8 = 31;
    pub const EAP_MESSAGE: u8 = 79;
    pub const MESSAGE_AUTHENTICATOR: u8 = 80;
}

/// Start a RADIUS authentication UDP server. The server runs until
/// the supplied `shutdown` future resolves.
pub async fn run_radius_server(
    bind_addr: std::net::SocketAddr,
    shared_secret: Vec<u8>,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> QidResult<()> {
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| QidError::Internal {
            message: format!("RADIUS bind failed: {e}"),
        })?;
    run_radius_server_with_socket(
        socket,
        shared_secret,
        Arc::new(|_, _| RadiusAccessDecision::Reject {
            reply_message: "RADIUS access policy is not configured".to_string(),
        }),
        shutdown,
    )
    .await
}

pub async fn run_radius_server_with_socket(
    socket: tokio::net::UdpSocket,
    shared_secret: Vec<u8>,
    authorizer: RadiusAccessAuthorizer,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> QidResult<()> {
    let socket = Arc::new(socket);
    let mut buffer = vec![0u8; 4096];
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => return Ok(()),
            received = socket.recv_from(&mut buffer) => {
                let (size, peer) = match received {
                    Ok(received) => received,
                    Err(_) => continue,
                };
                let packet = buffer[..size].to_vec();
                let secret = shared_secret.clone();
                let socket = socket.clone();
                let authorizer = authorizer.clone();
                tokio::spawn(async move {
                    let _ = handle_radius_access_request_with_authorizer(
                        &socket,
                        peer,
                        packet,
                        &secret,
                        authorizer.as_ref(),
                    )
                    .await;
                });
            }
        }
    }
}

/// Start a RADIUS accounting UDP server.  Accepts Accounting-Request
/// packets and responds with Accounting-Response after authenticator
/// validation.
pub async fn run_radius_accounting_server(
    bind_addr: std::net::SocketAddr,
    shared_secret: Vec<u8>,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> QidResult<()> {
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| QidError::Internal {
            message: format!("RADIUS accounting bind failed: {e}"),
        })?;
    run_radius_accounting_server_with_socket(socket, shared_secret, shutdown).await
}

pub async fn run_radius_accounting_server_with_socket(
    socket: tokio::net::UdpSocket,
    shared_secret: Vec<u8>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> QidResult<()> {
    let socket = Arc::new(socket);
    let mut buffer = vec![0u8; 4096];
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => return Ok(()),
            received = socket.recv_from(&mut buffer) => {
                let (size, peer) = match received {
                    Ok(received) => received,
                    Err(_) => continue,
                };
                let packet = buffer[..size].to_vec();
                let secret = shared_secret.clone();
                let socket = socket.clone();
                tokio::spawn(async move {
                    let _ = handle_radius_accounting_request(&socket, peer, packet, &secret).await;
                });
            }
        }
    }
}

/// Start a RADIUS CoA / Disconnect UDP server (RFC 5176).  Accepts
/// CoA-Request and Disconnect-Request packets and responds with their
/// respective ACK.  Override `handle_radius_coa_request` for
/// production use.
pub async fn run_radius_coa_server(
    bind_addr: std::net::SocketAddr,
    shared_secret: Vec<u8>,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> QidResult<()> {
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| QidError::Internal {
            message: format!("RADIUS CoA bind failed: {e}"),
        })?;
    run_radius_coa_server_with_socket(socket, shared_secret, shutdown).await
}

pub async fn run_radius_coa_server_with_socket(
    socket: tokio::net::UdpSocket,
    shared_secret: Vec<u8>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> QidResult<()> {
    let socket = Arc::new(socket);
    let mut buffer = vec![0u8; 4096];
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => return Ok(()),
            received = socket.recv_from(&mut buffer) => {
                let (size, peer) = match received {
                    Ok(received) => received,
                    Err(_) => continue,
                };
                let packet = buffer[..size].to_vec();
                let secret = shared_secret.clone();
                let socket = socket.clone();
                tokio::spawn(async move {
                    let _ = handle_radius_coa_request(&socket, peer, packet, &secret).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_username_is_rejected() {
        let request = RadiusPacket {
            code: RadiusCode::AccessRequest,
            identifier: 1,
            authenticator: [0u8; 16],
            attributes: Vec::new(),
        };
        let (code, attributes) =
            decide_radius_response("", &request, &|_, _| RadiusAccessDecision::Accept {
                reply_message: "accepted".to_string(),
                session_timeout_seconds: Some(3600),
            });
        assert_eq!(code, RadiusCode::AccessReject);
        assert_eq!(attributes[0].kind, attrs::REPLY_MESSAGE);
    }

    #[test]
    fn named_user_is_rejected_without_authorizer_approval() {
        let request = RadiusPacket {
            code: RadiusCode::AccessRequest,
            identifier: 1,
            authenticator: [0u8; 16],
            attributes: Vec::new(),
        };
        let (code, attributes) =
            decide_radius_response("alice", &request, &|_, _| RadiusAccessDecision::Reject {
                reply_message: "not authorized".to_string(),
            });
        assert_eq!(code, RadiusCode::AccessReject);
        assert!(attributes.iter().any(|a| a.kind == attrs::REPLY_MESSAGE));
    }

    #[test]
    fn named_user_is_accepted_with_authorizer_approval() {
        let request = RadiusPacket {
            code: RadiusCode::AccessRequest,
            identifier: 1,
            authenticator: [0u8; 16],
            attributes: Vec::new(),
        };
        let (code, attributes) =
            decide_radius_response("alice", &request, &|_, _| RadiusAccessDecision::Accept {
                reply_message: "accepted".to_string(),
                session_timeout_seconds: Some(3600),
            });
        assert_eq!(code, RadiusCode::AccessAccept);
        assert!(attributes.iter().any(|a| a.kind == attrs::SESSION_TIMEOUT));
    }
}
