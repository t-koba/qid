//! Workload CA custody: use the encrypted local keyring, never a JWT signing key.
use super::*;

pub(super) fn initialize(
    config: &QidConfig,
    state_dir: &Path,
    protector: Option<&PassphraseProtector>,
) -> anyhow::Result<BTreeMap<String, WorkloadCaMaterial>> {
    let mut cas = BTreeMap::new();
    if !matches!(config.profile, DeploymentProfile::Workload) {
        return Ok(cas);
    }
    config.validate_workload_ca_keys()?;
    let protector = protector.context(
        "workload CAs require QID_KEY_PASSPHRASE or crypto.key_passphrase_file before loading or generating private keys",
    )?;
    if state_dir.join("workload-ca.pem").exists() || state_dir.join("workload-ca-key.pem").exists()
    {
        bail!(
            "legacy workload-ca.pem / workload-ca-key.pem found; no files changed: preserve both files, verify their CA/key match, and explicitly provision that identity into the dedicated encrypted keyring and its .ca.pem certificate before removing legacy files from the active state directory; see docs/configuration.md"
        );
    }
    let configured_keyring_files = config
        .crypto
        .keyrings
        .iter()
        .map(|keyring| {
            let (private, _) =
                signing_key_paths(state_dir, &keyring.name, &config.crypto.default_alg);
            encrypted_key_path(&private)
        })
        .collect::<HashSet<_>>();
    let mut public_keys = HashSet::new();
    for realm in &config.realms {
        let name = realm
            .protocols
            .workload
            .workload_ca_key_ref
            .as_deref()
            .context("missing workload CA reference")?;
        let safe_name = safe_keyring_file_component(name);
        let successor_prefix = format!("signing-key-{safe_name}-ES256-");
        let successor_exists = match std::fs::read_dir(state_dir) {
            Ok(entries) => {
                let mut found = false;
                for entry in entries {
                    let entry = entry?;
                    let path = entry.path();
                    if configured_keyring_files.contains(&path) {
                        continue;
                    }
                    let file_name = entry.file_name();
                    let file_name = file_name.to_string_lossy();
                    found |=
                        file_name.starts_with(&successor_prefix) && file_name.ends_with(".pem.enc");
                }
                found
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if successor_exists {
            bail!(
                "workload CA {name}: keyring successor files are not supported; provision an explicit CA trust rotation instead of silently ignoring the successor"
            );
        }
        let (private, public) = signing_key_paths(state_dir, name, "ES256");
        let encrypted = encrypted_key_path(&private);
        let certificate = public.with_extension("ca.pem");
        let initialized_marker = certificate.with_extension("ca.state");
        let expected_marker = format!("qid-workload-ca-v1:{name}\n");
        let initialized = if initialized_marker.exists() {
            if std::fs::read_to_string(&initialized_marker)? != expected_marker {
                bail!(
                    "workload CA {name}: invalid initialization marker; restore the recorded state or plan an explicit trust rotation"
                );
            }
            true
        } else {
            false
        };
        if private.exists() || backup_key_path(&private).exists() {
            bail!(
                "workload CA {name}: plaintext key or backup found; explicitly provision encrypted material and remove plaintext from active state; no automatic migration"
            );
        }
        let has_ca_material = encrypted.exists() || public.exists() || certificate.exists();
        if initialized && !has_ca_material {
            bail!(
                "workload CA {name}: the initialization marker proves this CA was previously provisioned, but all key/certificate material is missing; restore it or plan an explicit trust rotation"
            );
        }
        if has_ca_material && (!encrypted.exists() || !certificate.exists()) {
            bail!(
                "workload CA {name}: incomplete existing material; restore the matching encrypted key and .ca.pem certificate from backup; refusing to generate a replacement"
            );
        }
        if !has_ca_material {
            // Generate via the same protected local keyring path as other signers.
            load_or_generate_local_keyring(state_dir, name, "ES256", Some(protector))?;
        }
        let envelope = parse_encrypted_key(&std::fs::read_to_string(&encrypted)?)?;
        if envelope.kid != name || envelope.alg != "ES256" {
            bail!(
                "workload CA {name}: encrypted key metadata does not match its reference/algorithm"
            );
        }
        let private_key_pem = protector.unseal(&envelope)?;
        let key = rcgen::KeyPair::from_pem(&private_key_pem)?;
        if key.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 {
            bail!("workload CA {name}: key must be ES256");
        }
        if !public_keys.insert(key.public_key_der()) {
            bail!(
                "workload CA {name}: private key is reused across realms; provision distinct realm CAs"
            );
        }
        let certificate_pem = if certificate.exists() {
            std::fs::read_to_string(&certificate)?
        } else {
            let mut params = rcgen::CertificateParams::default();
            params.distinguished_name.push(
                rcgen::DnType::CommonName,
                format!("qid workload CA {}", realm.id),
            );
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
            params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            let pem = params.self_signed(&key)?.pem();
            std::fs::write(&certificate, &pem)?;
            pem
        };
        validate_certificate(&certificate_pem, &key).with_context(|| format!("workload CA {name}: invalid or mismatched CA certificate; restore matching material, no files replaced"))?;
        if !initialized {
            std::fs::write(&initialized_marker, expected_marker)?;
        }
        cas.insert(
            realm.id.clone(),
            WorkloadCaMaterial {
                key_ref: name.to_string(),
                certificate_pem,
                private_key_pem,
            },
        );
    }
    Ok(cas)
}

fn validate_certificate(pem: &str, key: &rcgen::KeyPair) -> anyhow::Result<()> {
    use x509_parser::prelude::*;
    let (rest, pem) =
        parse_x509_pem(pem.as_bytes()).map_err(|_| anyhow::anyhow!("invalid CA PEM"))?;
    if rest.iter().any(|b| !b.is_ascii_whitespace()) || pem.label != "CERTIFICATE" {
        bail!("expected exactly one CA certificate");
    }
    let (rest, cert) = X509Certificate::from_der(&pem.contents)?;
    if !rest.is_empty()
        || cert.public_key().raw != key.public_key_der()
        || !cert.validity().is_valid()
        || !cert.basic_constraints()?.is_some_and(|extension| {
            extension.critical
                && extension.value.ca
                && extension
                    .value
                    .path_len_constraint
                    .is_none_or(|path_len| path_len == 0)
        })
        || !cert
            .key_usage()?
            .is_some_and(|extension| extension.critical && extension.value.key_cert_sign())
        || cert.subject() != cert.issuer()
    {
        bail!(
            "CA must be current, self-signed, have critical CA constraints with pathLen absent or zero and keyCertSign usage, and match its private key"
        );
    }
    cert.verify_signature(None)?;
    Ok(())
}
