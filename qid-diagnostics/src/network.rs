use super::*;

pub(crate) fn check_listen(config: &QidConfig) -> CheckItem {
    match config.server.listen.parse::<std::net::SocketAddr>() {
        Ok(_) => check_ok(
            "server.listen",
            format!("listen address: {}", config.server.listen),
        ),
        Err(e) => check_error("server.listen", format!("invalid socket address: {e}")),
    }
}

pub(crate) fn check_public_base_url(config: &QidConfig) -> CheckItem {
    match url::Url::parse(&config.server.public_base_url) {
        Ok(_) => check_ok(
            "server.public_base_url",
            format!("base URL: {}", config.server.public_base_url),
        ),
        Err(e) => check_error("server.public_base_url", format!("invalid URL: {e}")),
    }
}

pub(crate) fn check_metrics_listen(config: &QidConfig) -> CheckItem {
    match config
        .observability
        .metrics
        .listen
        .parse::<std::net::SocketAddr>()
    {
        Ok(addr) if addr.ip().is_unspecified() => check_warning(
            "metrics.listen",
            format!("metrics listener is bound to all interfaces: {addr}"),
        ),
        Ok(addr) => check_ok(
            "metrics.listen",
            format!("metrics listener address is valid: {addr}"),
        ),
        Err(err) => check_error(
            "metrics.listen",
            format!("metrics listener address is invalid: {err}"),
        ),
    }
}

/// Check remote signer configuration without probing external systems.
///
/// `qidc check` validates deployability of the configuration itself. KMS/HSM
/// reachability is a runtime concern: if a sample keeps a dummy endpoint, the
/// daemon should record signer access failures when it actually tries to use it.
pub(crate) fn check_remote_signer_configuration(config: &QidConfig) -> Vec<CheckItem> {
    config
        .crypto
        .keyrings
        .iter()
        .filter(|keyring| matches!(keyring.signer.r#type.as_str(), "kms" | "hsm" | "pkcs11"))
        .map(|keyring| {
            let uri = keyring.signer.uri.as_deref().unwrap_or("");
            let name = format!("remote_signer.{}", keyring.name);
            if uri.is_empty() {
                return check_error(
                    &name,
                    format!(
                        "{} keyring {} has no uri configured",
                        keyring.signer.r#type, keyring.name
                    ),
                );
            }
            check_ok(
                &name,
                format!(
                    "{} keyring {} uri is configured; signer access is verified at runtime",
                    keyring.signer.r#type, keyring.name
                ),
            )
        })
        .collect()
}
