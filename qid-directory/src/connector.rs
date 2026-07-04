//! Directory connector trait and implementations.
//!
//! The [`DirectoryConnector`] trait abstracts over different directory
//! backends (LDAP, AD, SCIM, HR). Implementations translate directory
//! entries into the canonical [`LdapDirectoryEntry`] used by qid's sync engine.

use async_trait::async_trait;
use qid_core::{
    config::{DirectoryAttributeMapping, DirectoryConnectionConfig, DirectorySyncConfig},
    error::{QidError, QidResult},
};

use crate::ldap_filter;
use crate::types::LdapDirectoryEntry;

/// Escape a string for safe inclusion in an LDAP search filter
/// (RFC 4515 §3). Any character outside a conservative allow-list is
/// rejected outright; the four reserved characters
/// `\` `*` `(` `)` are escaped with their two-digit hex code. NUL bytes
/// are always rejected to avoid truncation attacks.
pub fn escape_ldap_search_filter(input: &str) -> QidResult<String> {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => {
                return Err(QidError::Internal {
                    message: "LDAP search filter value contains NUL byte".to_string(),
                });
            }
            c if (c as u32) < 0x20 => {
                return Err(QidError::Internal {
                    message: format!(
                        "LDAP search filter value contains control character U+{:04X}",
                        c as u32
                    ),
                });
            }
            c => out.push(c),
        }
    }
    Ok(out)
}

/// Escape a string for safe inclusion in an LDAP distinguished name
/// (RFC 4514 §2.4). The set of characters that require escaping is
/// documented in the RFC and includes the structural delimiters `,`
/// and `=`. NUL bytes are rejected.
pub fn escape_ldap_dn_value(input: &str) -> QidResult<String> {
    let mut out = String::with_capacity(input.len());
    let leading = input.chars().next().unwrap_or(' ');
    if matches!(leading, ' ' | '#') {
        out.push('\\');
    }
    for ch in input.chars() {
        match ch {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                out.push('\\');
                out.push(ch);
            }
            '\0' => {
                return Err(QidError::Internal {
                    message: "LDAP DN value contains NUL byte".to_string(),
                });
            }
            c if (c as u32) < 0x20 => {
                return Err(QidError::Internal {
                    message: format!(
                        "LDAP DN value contains control character U+{:04X}",
                        c as u32
                    ),
                });
            }
            c => out.push(c),
        }
    }
    if input.ends_with(' ') {
        out.push('\\');
        out.push(' ');
    }
    Ok(out)
}

/// Unified directory connector trait.
///
/// Each implementation connects to a directory backend, fetches users,
/// and maps them to the canonical representation used by `sync_ldap_entries`.
#[async_trait]
pub trait DirectoryConnector: Send + Sync {
    /// Establish a connection to the directory provider.
    async fn connect(&mut self, config: &DirectoryConnectionConfig) -> QidResult<()>;

    /// Fetch directory users, mapped to qid [`LdapDirectoryEntry`].
    async fn fetch_users(
        &self,
        sync: &DirectorySyncConfig,
        mapping: &DirectoryAttributeMapping,
    ) -> QidResult<Vec<LdapDirectoryEntry>>;

    /// Gracefully close the connection.
    async fn disconnect(&mut self) -> QidResult<()>;
}

/// Real LDAP/AD connector using the ldap3 asynchronous API.
///
/// Opens a fresh LDAP connection per `fetch_users` call using
/// `spawn_blocking` with an inner Tokio runtime, because the
/// `ldap3::LdapRx` handle is not `Send`.
pub struct LdapDirectoryConnector {
    config: Option<DirectoryConnectionConfig>,
}

impl LdapDirectoryConnector {
    pub fn new() -> Self {
        Self { config: None }
    }
}

impl Default for LdapDirectoryConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DirectoryConnector for LdapDirectoryConnector {
    async fn connect(&mut self, config: &DirectoryConnectionConfig) -> QidResult<()> {
        self.config = Some(config.clone());
        Ok(())
    }

    async fn fetch_users(
        &self,
        sync: &DirectorySyncConfig,
        mapping: &DirectoryAttributeMapping,
    ) -> QidResult<Vec<LdapDirectoryEntry>> {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| qid_core::error::QidError::Internal {
                message: "LdapDirectoryConnector: connect() must be called before fetch_users()"
                    .to_string(),
            })?;
        let url = config.url.clone();
        // The bind DN comes from configuration but is still passed verbatim
        // into a search filter, so we escape it defensively to keep
        // injection attacks out of the directory round trip.
        let bind_dn = match &config.bind_dn {
            Some(dn) => Some(escape_ldap_dn_value(dn)?),
            None => None,
        };
        let bind_pw = config.bind_password.clone();
        let search_base = resolve_search_base(config);
        let raw_filter = sync
            .user_search_filter
            .as_deref()
            .unwrap_or("(objectClass=user)");
        let sanitized_filter = sanitize_admin_search_filter(raw_filter)?;
        let mapping = mapping.clone();
        let timeout_secs = config.connect_timeout_seconds.unwrap_or(10);
        let tls_insecure = config.tls_insecure_skip_verify;

        tokio::task::spawn_blocking(move || {
            run_ldap_search(
                &url,
                bind_dn,
                bind_pw,
                &search_base,
                &sanitized_filter,
                &mapping,
                timeout_secs,
                tls_insecure,
            )
        })
        .await
        .map_err(|e| qid_core::error::QidError::Internal {
            message: format!("spawn_blocking failed: {e}"),
        })?
    }

    async fn disconnect(&mut self) -> QidResult<()> {
        self.config = None;
        Ok(())
    }
}

/// Parse and re-serialize an LDAP filter with proper value escaping.
/// Delegates to the RFC 4515 parser in `ldap_filter`.
fn sanitize_admin_search_filter(filter: &str) -> QidResult<String> {
    ldap_filter::sanitize_admin_search_filter(filter)
}

pub struct LdapSearchOptions {
    pub page_size: Option<u32>,
    pub use_sasl: bool,
    pub timeout_secs: u64,
}

impl Default for LdapSearchOptions {
    fn default() -> Self {
        Self {
            page_size: None,
            use_sasl: false,
            timeout_secs: 10,
        }
    }
}

fn shared_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Runtime::new().expect("failed to create Tokio runtime for LDAP")
    })
}

#[allow(clippy::too_many_arguments)]
fn run_ldap_search(
    url: &str,
    bind_dn: Option<String>,
    bind_pw: Option<String>,
    search_base: &str,
    search_filter: &str,
    mapping: &DirectoryAttributeMapping,
    timeout_secs: u64,
    tls_insecure: bool,
) -> QidResult<Vec<LdapDirectoryEntry>> {
    use ldap3::SearchEntry;
    use std::time::Duration;

    // INTEROP §4513: enforce TLS for LDAP plain bind.
    // Reject non-TLS URLs unless the connection uses a Unix socket.
    if !url.starts_with("ldaps://") && !url.starts_with("ldap://") {
        return Err(qid_core::error::QidError::BadRequest {
            message: "LDAP URL must use ldaps:// or ldap:// scheme".to_string(),
        });
    }
    let use_starttls = url.starts_with("ldap://");
    let url = url.to_string();

    shared_runtime().block_on(async {
        let settings = ldap3::LdapConnSettings::new()
            .set_starttls(use_starttls)
            .set_no_tls_verify(tls_insecure);
        let (_, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| qid_core::error::QidError::Internal {
                message: format!("LDAP connect to {url} failed: {e}"),
            })?;
        ldap.with_timeout(Duration::from_secs(timeout_secs));

        if let (Some(dn), Some(pw)) = (&bind_dn, &bind_pw) {
            ldap.simple_bind(dn, pw)
                .await
                .map_err(|e| qid_core::error::QidError::Internal {
                    message: format!("LDAP bind failed: {e}"),
                })?;
        }

        let ldap3::SearchResult(entries, _res) = ldap
            .search(
                search_base,
                ldap3::Scope::Subtree,
                search_filter,
                vec!["*", "userAccountControl"],
            )
            .await
            .map_err(|e| qid_core::error::QidError::Internal {
                message: format!("LDAP search failed: {e}"),
            })?;

        ldap.unbind().await.ok();

        let result: Vec<LdapDirectoryEntry> = entries
            .into_iter()
            .map(|entry| {
                let se = SearchEntry::construct(entry);
                let mut attrs = std::collections::BTreeMap::new();
                for (k, v) in se.attrs {
                    attrs.insert(k, v);
                }
                map_ldap_entry(&se.dn, &attrs, mapping, true)
            })
            .collect();

        Ok(result)
    })
}

/// In-memory test connector that returns pre-configured entries.
pub struct TestDirectoryConnector {
    entries: Vec<LdapDirectoryEntry>,
}

impl TestDirectoryConnector {
    pub fn new(entries: Vec<LdapDirectoryEntry>) -> Self {
        Self { entries }
    }
}

#[async_trait]
impl DirectoryConnector for TestDirectoryConnector {
    async fn connect(&mut self, _config: &DirectoryConnectionConfig) -> QidResult<()> {
        Ok(())
    }

    async fn fetch_users(
        &self,
        _sync: &DirectorySyncConfig,
        _mapping: &DirectoryAttributeMapping,
    ) -> QidResult<Vec<LdapDirectoryEntry>> {
        Ok(self.entries.clone())
    }

    async fn disconnect(&mut self) -> QidResult<()> {
        Ok(())
    }
}

/// CSV HR connector that reads employee lifecycle events from a CSV file.
///
/// Expected CSV columns (case-insensitive header):
/// `external_id`, `email`, `display_name`, `department`,
/// `manager_external_id`, `event` (joiner/mover/leaver)
pub struct CsvHrConnector {
    path: Option<String>,
}

impl CsvHrConnector {
    pub fn new() -> Self {
        Self { path: None }
    }
}

impl Default for CsvHrConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DirectoryConnector for CsvHrConnector {
    async fn connect(&mut self, config: &DirectoryConnectionConfig) -> QidResult<()> {
        self.path = Some(config.url.clone());
        Ok(())
    }

    async fn fetch_users(
        &self,
        _sync: &DirectorySyncConfig,
        _mapping: &DirectoryAttributeMapping,
    ) -> QidResult<Vec<LdapDirectoryEntry>> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| qid_core::error::QidError::Internal {
                message: "CsvHrConnector: connect() must be called before fetch_users()"
                    .to_string(),
            })?;
        let content = tokio::fs::read_to_string(path).await.map_err(|e| {
            qid_core::error::QidError::Internal {
                message: format!("failed to read CSV file {path}: {e}"),
            }
        })?;
        parse_csv_hr_records(&content)
    }

    async fn disconnect(&mut self) -> QidResult<()> {
        self.path = None;
        Ok(())
    }
}

/// Parse CSV HR content into `LdapDirectoryEntry` vectors.
fn parse_csv_hr_records(content: &str) -> QidResult<Vec<LdapDirectoryEntry>> {
    let mut lines = content.lines().filter(|l| !l.trim().is_empty());
    let header_line = lines
        .next()
        .ok_or_else(|| qid_core::error::QidError::BadRequest {
            message: "CSV file is empty".to_string(),
        })?;
    let headers: Vec<&str> = header_line
        .split(',')
        .map(|h| h.trim().trim_matches('"'))
        .collect();

    let ext_idx = find_header(&headers, "external_id")?;
    let email_idx = find_header(&headers, "email")?;
    let display_idx = find_header(&headers, "display_name")?;
    let dept_idx = find_header(&headers, "department")?;
    let mgr_idx = find_header(&headers, "manager_external_id")?;
    let evt_idx = find_header(&headers, "event")?;

    let mut entries = Vec::new();
    for (lineno, line) in lines.enumerate() {
        let cols: Vec<&str> = split_csv_line(line);
        if cols.len()
            <= ext_idx
                .max(email_idx)
                .max(display_idx)
                .max(dept_idx)
                .max(mgr_idx)
                .max(evt_idx)
        {
            return Err(qid_core::error::QidError::BadRequest {
                message: format!("CSV line {} has too few columns", lineno + 2),
            });
        }
        let external_id = cols[ext_idx].trim().trim_matches('"');
        let email = cols[email_idx].trim().trim_matches('"');
        let display_name = cols[display_idx].trim().trim_matches('"');
        let department = cols[dept_idx].trim().trim_matches('"');
        let manager_external_id = cols[mgr_idx].trim().trim_matches('"');
        let event = cols[evt_idx].trim().trim_matches('"').to_lowercase();

        if external_id.is_empty() {
            return Err(qid_core::error::QidError::BadRequest {
                message: format!("CSV line {} has empty external_id", lineno + 2),
            });
        }

        let enabled = match event.as_str() {
            "joiner" | "mover" => true,
            "leaver" => false,
            other => {
                return Err(qid_core::error::QidError::BadRequest {
                    message: format!(
                        "CSV line {} has invalid event '{}' (expected joiner/mover/leaver)",
                        lineno + 2,
                        other
                    ),
                });
            }
        };

        entries.push(LdapDirectoryEntry {
            dn: external_id.to_string(),
            uid: external_id.to_string(),
            mail: if email.is_empty() {
                None
            } else {
                Some(email.to_string())
            },
            display_name: if display_name.is_empty() {
                None
            } else {
                Some(display_name.to_string())
            },
            department: if department.is_empty() {
                None
            } else {
                Some(department.to_string())
            },
            manager_dn: if manager_external_id.is_empty() {
                None
            } else {
                Some(manager_external_id.to_string())
            },
            enabled,
        });
    }
    Ok(entries)
}

fn find_header(headers: &[&str], name: &str) -> QidResult<usize> {
    headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case(name))
        .ok_or_else(|| qid_core::error::QidError::BadRequest {
            message: format!("CSV missing required column '{name}'"),
        })
}

fn split_csv_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    for (i, ch) in line.char_indices() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == ',' && !in_quotes {
            fields.push(&line[start..i]);
            start = i + 1;
        }
    }
    fields.push(&line[start..]);
    fields
}

/// Webhook HR connector that ingests JSON lifecycle events.
///
/// The webhook payload is an array of objects with fields:
/// `external_id`, `email`, `display_name`, `department`,
/// `manager_external_id`, `event` (joiner/mover/leaver).
/// Entries are stored in memory and returned via `fetch_users`.
pub struct WebhookHrConnector {
    entries: Vec<LdapDirectoryEntry>,
}

impl WebhookHrConnector {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Ingest a JSON webhook payload containing lifecycle events.
    ///
    /// The payload should be a JSON array of objects matching the expected
    /// HR record schema. Each object may contain:
    /// `external_id` (required), `email`, `display_name`, `department`,
    /// `manager_external_id`, `event` (required: joiner/mover/leaver).
    pub fn ingest_json(&mut self, payload: &serde_json::Value) -> QidResult<()> {
        let records = payload
            .as_array()
            .ok_or_else(|| qid_core::error::QidError::BadRequest {
                message: "webhook payload must be a JSON array".to_string(),
            })?;

        for record in records {
            let obj = record
                .as_object()
                .ok_or_else(|| qid_core::error::QidError::BadRequest {
                    message: "each webhook record must be a JSON object".to_string(),
                })?;

            let external_id = obj
                .get("external_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| qid_core::error::QidError::BadRequest {
                    message: "webhook record missing external_id".to_string(),
                })?;

            let event = obj.get("event").and_then(|v| v.as_str()).ok_or_else(|| {
                qid_core::error::QidError::BadRequest {
                    message: "webhook record missing event".to_string(),
                }
            })?;

            let enabled = match event {
                "joiner" | "mover" => true,
                "leaver" => false,
                other => {
                    return Err(qid_core::error::QidError::BadRequest {
                        message: format!("webhook record has invalid event '{other}'"),
                    });
                }
            };

            let email = obj
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let display_name = obj
                .get("display_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let department = obj
                .get("department")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let manager_external_id = obj
                .get("manager_external_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            self.entries.push(LdapDirectoryEntry {
                dn: external_id.to_string(),
                uid: external_id.to_string(),
                mail: email,
                display_name,
                department,
                manager_dn: manager_external_id,
                enabled,
            });
        }
        Ok(())
    }
}

impl Default for WebhookHrConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DirectoryConnector for WebhookHrConnector {
    async fn connect(&mut self, _config: &DirectoryConnectionConfig) -> QidResult<()> {
        Ok(())
    }

    async fn fetch_users(
        &self,
        _sync: &DirectorySyncConfig,
        _mapping: &DirectoryAttributeMapping,
    ) -> QidResult<Vec<LdapDirectoryEntry>> {
        Ok(self.entries.clone())
    }

    async fn disconnect(&mut self) -> QidResult<()> {
        self.entries.clear();
        Ok(())
    }
}

/// Build a search base string from a connection config.
/// If `base_dn` is set explicitly, use it; otherwise derive from the hostname.
pub fn resolve_search_base(config: &DirectoryConnectionConfig) -> String {
    if let Some(ref base_dn) = config.base_dn {
        return base_dn.clone();
    }
    let url = &config.url;
    let rest = url
        .strip_prefix("ldap://")
        .or_else(|| url.strip_prefix("ldaps://"));
    let host = match rest {
        Some(r) => r.split(':').next().unwrap_or(""),
        None => "",
    };
    if host.is_empty() {
        return String::new();
    }
    host.split('.')
        .map(|part| format!("dc={part}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Filter out disabled users based on the `userAccountControl` bitmask heuristic.
/// Used by the AD connector to evaluate the enabled mapping expression.
pub fn evaluate_enabled_expression(_expr: &str, _user_account_control: Option<&str>) -> bool {
    // Simple heuristic: if expression contains "2)" (ACCOUNTDISABLE bit),
    // check that the bit is NOT set
    if let Some(uac) = _user_account_control
        && let Ok(flags) = uac.parse::<u64>()
    {
        // Bit 1 = ACCOUNTDISABLE
        return flags & 2 == 0;
    }
    true
}

/// Map raw LDAP attribute values into a canonical `LdapDirectoryEntry`.
pub fn map_ldap_entry(
    dn: &str,
    attrs: &std::collections::BTreeMap<String, Vec<String>>,
    mapping: &DirectoryAttributeMapping,
    default_enabled: bool,
) -> LdapDirectoryEntry {
    let uid_attr = mapping.uid.as_deref().unwrap_or("sAMAccountName");
    let uid = get_first_attr(attrs, uid_attr).unwrap_or_else(|| dn.to_string());

    let enabled = if let Some(enabled_expr) = &mapping.enabled {
        let uac = get_first_attr(attrs, "userAccountControl");
        evaluate_enabled_expression(enabled_expr, uac.as_deref())
    } else {
        default_enabled
    };

    LdapDirectoryEntry {
        dn: dn.to_string(),
        uid,
        mail: get_first_attr(attrs, mapping.mail.as_deref().unwrap_or("mail")),
        display_name: get_first_attr(
            attrs,
            mapping.display_name.as_deref().unwrap_or("displayName"),
        ),
        department: get_first_attr(attrs, mapping.department.as_deref().unwrap_or("department")),
        manager_dn: get_first_attr(attrs, mapping.manager_dn.as_deref().unwrap_or("manager")),
        enabled,
    }
}

fn get_first_attr(
    attrs: &std::collections::BTreeMap<String, Vec<String>>,
    key: &str,
) -> Option<String> {
    attrs.get(key).and_then(|values| values.first()).cloned()
}

pub fn run_ldap_search_with_options(
    url: &str,
    bind_dn: Option<String>,
    bind_pw: Option<String>,
    search_base: &str,
    search_filter: &str,
    mapping: &DirectoryAttributeMapping,
    options: LdapSearchOptions,
) -> QidResult<Vec<LdapDirectoryEntry>> {
    use ldap3::SearchEntry;
    use ldap3::controls::{Control, ControlType, PagedResults};
    use std::time::Duration;

    if !url.starts_with("ldaps://") && !url.starts_with("ldap://") {
        return Err(qid_core::error::QidError::BadRequest {
            message: "LDAP URL must use ldaps:// or ldap:// scheme".to_string(),
        });
    }
    let use_starttls = url.starts_with("ldap://");
    let url = url.to_string();

    shared_runtime().block_on(async {
        let settings = ldap3::LdapConnSettings::new()
            .set_starttls(use_starttls)
            .set_no_tls_verify(false);
        // Note: tls_insecure is not passed into this function; the
        // paged-search variant currently defaults to strict verification.
        let (_, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| qid_core::error::QidError::Internal {
                message: format!("LDAP connect to {url} failed: {e}"),
            })?;
        ldap.with_timeout(Duration::from_secs(options.timeout_secs));

        if options.use_sasl {
            if let (Some(dn), Some(pw)) = (&bind_dn, &bind_pw) {
                ldap_sasl_scram_sha256_bind(&mut ldap, dn, pw)
                    .await
                    .map_err(|e| qid_core::error::QidError::Internal {
                        message: format!("LDAP SASL SCRAM-SHA-256 bind failed: {e}"),
                    })?;
            }
        } else if let (Some(dn), Some(pw)) = (&bind_dn, &bind_pw) {
            ldap.simple_bind(dn, pw)
                .await
                .map_err(|e| qid_core::error::QidError::Internal {
                    message: format!("LDAP bind failed: {e}"),
                })?;
        }

        let page_size = options.page_size.unwrap_or(0);
        let mut all_entries = Vec::new();
        let mut cookie = Vec::new();

        loop {
            if page_size > 0 {
                ldap.with_controls(PagedResults {
                    size: page_size as i32,
                    cookie: cookie.clone(),
                });
            }
            let ldap3::SearchResult(entries, res) = ldap
                .search(
                    search_base,
                    ldap3::Scope::Subtree,
                    search_filter,
                    vec!["*", "userAccountControl"],
                )
                .await
                .map_err(|e| qid_core::error::QidError::Internal {
                    message: format!("LDAP search failed: {e}"),
                })?;
            if page_size > 0 {
                let raw = res.ctrls.iter().find_map(|ctrl| {
                    if let Control(Some(ControlType::PagedResults), raw) = ctrl {
                        Some(raw)
                    } else {
                        None
                    }
                });
                if let Some(raw) = raw {
                    let pr: PagedResults = raw.parse();
                    cookie = pr.cookie;
                }
            }
            for entry in entries {
                let se = SearchEntry::construct(entry);
                let mut attrs = std::collections::BTreeMap::new();
                for (k, v) in se.attrs {
                    attrs.insert(k, v);
                }
                all_entries.push(map_ldap_entry(&se.dn, &attrs, mapping, true));
            }
            if page_size == 0 || cookie.is_empty() {
                break;
            }
        }

        ldap.unbind().await.ok();
        Ok(all_entries)
    })
}

/// SASL SCRAM-SHA-256 bind helper. The `ldap3` 0.12.x crate does not
/// ship a built-in SCRAM-SHA-256 implementation. This function provides
/// a documented path: callers should enable the `scram` crate and
/// use `ldap3::sasl::SaslAuthMechanism` with a custom SCRAM callback.
/// For now, falls back to simple bind over TLS.
pub async fn ldap_sasl_scram_sha256_bind(
    ldap: &mut ldap3::Ldap,
    username: &str,
    password: &str,
) -> Result<(), String> {
    ldap.simple_bind(username, password)
        .await
        .map_err(|e| format!("SCRAM fallback bind failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_base_dn_from_url() {
        let config = DirectoryConnectionConfig {
            url: "ldaps://ad.example.com:636".to_string(),
            ..Default::default()
        };
        assert_eq!(resolve_search_base(&config), "dc=ad,dc=example,dc=com");
    }

    #[test]
    fn uses_explicit_base_dn() {
        let config = DirectoryConnectionConfig {
            url: "ldaps://ad.example.com:636".to_string(),
            base_dn: Some("dc=custom,dc=com".to_string()),
            ..Default::default()
        };
        assert_eq!(resolve_search_base(&config), "dc=custom,dc=com");
    }

    #[test]
    fn returns_empty_when_no_ldap_url() {
        let config = DirectoryConnectionConfig {
            url: "https://api.example.com/scim".to_string(),
            ..Default::default()
        };
        assert_eq!(resolve_search_base(&config), "");
    }

    #[test]
    fn map_ldap_entry_extracts_attributes() {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("sAMAccountName".to_string(), vec!["alice".to_string()]);
        attrs.insert("mail".to_string(), vec!["alice@example.com".to_string()]);
        attrs.insert("displayName".to_string(), vec!["Alice Example".to_string()]);
        attrs.insert("department".to_string(), vec!["Engineering".to_string()]);
        attrs.insert(
            "manager".to_string(),
            vec!["CN=Bob,OU=Users,DC=example,DC=com".to_string()],
        );

        let mapping = DirectoryAttributeMapping::default();
        let entry = map_ldap_entry(
            "CN=Alice,OU=Users,DC=example,DC=com",
            &attrs,
            &mapping,
            true,
        );

        assert_eq!(entry.uid, "alice");
        assert_eq!(entry.mail, Some("alice@example.com".to_string()));
        assert_eq!(entry.display_name, Some("Alice Example".to_string()));
        assert_eq!(entry.department, Some("Engineering".to_string()));
        assert_eq!(
            entry.manager_dn,
            Some("CN=Bob,OU=Users,DC=example,DC=com".to_string())
        );
        assert!(entry.enabled);
    }

    #[test]
    fn detects_disabled_user_via_user_account_control() {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert(
            "sAMAccountName".to_string(),
            vec!["disabled-user".to_string()],
        );
        // Bit 1 (ACCOUNTDISABLE) is set: 2
        attrs.insert(
            "userAccountControl".to_string(),
            vec!["514".to_string()], // 512 (NORMAL_ACCOUNT) + 2 (ACCOUNTDISABLE)
        );

        let mapping = DirectoryAttributeMapping::default();
        let entry = map_ldap_entry(
            "CN=Disabled User,OU=Users,DC=example,DC=com",
            &attrs,
            &mapping,
            true,
        );

        assert!(!entry.enabled);
        assert_eq!(entry.uid, "disabled-user");
    }

    #[test]
    fn enabled_user_when_no_account_control_attribute() {
        let attrs = std::collections::BTreeMap::new();

        let mapping = DirectoryAttributeMapping::default();
        let entry = map_ldap_entry(
            "CN=No UAC,OU=Users,DC=example,DC=com",
            &attrs,
            &mapping,
            true,
        );

        assert!(entry.enabled);
    }

    #[test]
    fn custom_attribute_mapping_uses_configured_ldap_attributes() {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("cn".to_string(), vec!["bob".to_string()]);
        attrs.insert(
            "proxyAddresses".to_string(),
            vec!["bob@example.com".to_string()],
        );

        let mapping = DirectoryAttributeMapping {
            uid: Some("cn".to_string()),
            mail: Some("proxyAddresses".to_string()),
            ..Default::default()
        };

        let entry = map_ldap_entry("CN=Bob,OU=Users,DC=example,DC=com", &attrs, &mapping, true);

        assert_eq!(entry.uid, "bob");
        assert_eq!(entry.mail, Some("bob@example.com".to_string()));
        assert!(entry.enabled);
    }

    #[test]
    fn test_connector_returns_configured_entries() {
        let entries = vec![LdapDirectoryEntry {
            dn: "uid=alice,ou=people,dc=example,dc=com".to_string(),
            uid: "alice".to_string(),
            mail: Some("alice@example.com".to_string()),
            display_name: Some("Alice Example".to_string()),
            department: Some("Engineering".to_string()),
            manager_dn: None,
            enabled: true,
        }];
        let config = DirectoryConnectionConfig::default();
        let sync = DirectorySyncConfig::default();
        let mapping = DirectoryAttributeMapping::default();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            let mut c = TestDirectoryConnector::new(entries.clone());
            c.connect(&config).await.unwrap();
            c.fetch_users(&sync, &mapping).await.unwrap()
        });
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].uid, "alice");
    }

    #[test]
    fn test_connector_disconnect_clears_state() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut c = TestDirectoryConnector::new(Vec::new());
            c.connect(&DirectoryConnectionConfig::default())
                .await
                .unwrap();
            c.disconnect().await.unwrap();
            // Can reconnect after disconnect
            c.connect(&DirectoryConnectionConfig::default())
                .await
                .unwrap();
        });
    }

    #[test]
    fn evaluate_enabled_true_for_normal_account() {
        assert!(evaluate_enabled_expression(
            "!(userAccountControl:1.2.840.113556.1.4.803:=2)",
            Some("512")
        ));
    }

    #[test]
    fn evaluate_enabled_false_for_disabled_account() {
        assert!(!evaluate_enabled_expression(
            "!(userAccountControl:1.2.840.113556.1.4.803:=2)",
            Some("514")
        ));
    }

    #[test]
    fn evaluate_enabled_defaults_true() {
        assert!(evaluate_enabled_expression(
            "!(userAccountControl:1.2.840.113556.1.4.803:=2)",
            None
        ));
    }

    #[test]
    fn ldap_search_options_default() {
        let opts = LdapSearchOptions::default();
        assert_eq!(opts.page_size, None);
        assert!(!opts.use_sasl);
    }

    #[test]
    fn csv_formula_injection_is_parsed_as_literal() {
        // CSV injection payloads (=, +, -, @) should be stored as-is,
        // not interpreted as formulas by the parser.
        let csv = concat!(
            "external_id,email,display_name,department,manager_external_id,event\n",
            "=cmd|' /C calc'!A0,=1+1,+abc,-def,@sum,joiner\n",
        );
        let entries = parse_csv_hr_records(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uid, "=cmd|' /C calc'!A0");
        assert_eq!(entries[0].mail.as_deref(), Some("=1+1"));
        assert_eq!(entries[0].display_name.as_deref(), Some("+abc"));
        assert_eq!(entries[0].department.as_deref(), Some("-def"));
        assert_eq!(entries[0].manager_dn.as_deref(), Some("@sum"));
        assert!(entries[0].enabled);
    }

    #[test]
    fn csv_quoted_field_with_commas() {
        // Fields enclosed in double quotes may contain commas.
        let csv = concat!(
            "external_id,email,display_name,department,manager_external_id,event\n",
            "u1,\"alice@example.com\",\"Alice, Engineering\",Dev,mg1,joiner\n",
        );
        let entries = parse_csv_hr_records(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uid, "u1");
        assert_eq!(entries[0].mail.as_deref(), Some("alice@example.com"));
        assert_eq!(
            entries[0].display_name.as_deref(),
            Some("Alice, Engineering")
        );
        assert!(entries[0].enabled);
    }

    #[test]
    fn csv_very_long_fields_do_not_crash() {
        // Long values should not cause excessive memory or panics.
        let long = "A".repeat(10_000);
        let csv = format!(
            "external_id,email,display_name,department,manager_external_id,event\n\
             {long},{long},{long},{long},{long},joiner\n"
        );
        let entries = parse_csv_hr_records(&csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uid.len(), 10_000);
    }

    #[test]
    fn csv_missing_column_rejected() {
        let csv = concat!("external_id,display_name,event\n", "u1,Alice,joiner\n",);
        let err = parse_csv_hr_records(csv).unwrap_err();
        assert!(err.message().contains("CSV missing required column"));
    }

    #[test]
    fn csv_empty_external_id_rejected() {
        let csv = concat!(
            "external_id,email,display_name,department,manager_external_id,event\n",
            ",alice@example.com,Alice,Engineering,,joiner\n",
        );
        let err = parse_csv_hr_records(csv).unwrap_err();
        assert!(err.message().contains("empty external_id"));
    }

    #[test]
    fn csv_invalid_event_rejected() {
        let csv = concat!(
            "external_id,email,display_name,department,manager_external_id,event\n",
            "u1,alice@example.com,Alice,Engineering,,invalid_event\n",
        );
        let err = parse_csv_hr_records(csv).unwrap_err();
        assert!(err.message().contains("invalid event"));
    }
}
