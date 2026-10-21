//! Directory connector trait and implementations.
//!
//! The [`DirectoryConnector`] trait abstracts over different directory
//! backends (LDAP, AD, SCIM, HR). Implementations translate directory
//! entries into the canonical [`LdapDirectoryEntry`] used by qid's sync engine.

use async_trait::async_trait;
use qid_core::config::{MAX_DIRECTORY_SEARCH_ENTRIES, bind_credentials, valid_bind_dn};
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

/// The bind DN to use, preserved as configured.
pub(crate) fn bind_dn_for(config: &DirectoryConnectionConfig) -> QidResult<Option<String>> {
    let Some(dn) = &config.bind_dn else {
        return Ok(None);
    };
    valid_bind_dn(dn)?;
    Ok(Some(dn.clone()))
}

/// Unified directory connector trait.
///
/// Each implementation connects to a directory backend, fetches users,
/// and maps them to the canonical representation used by `sync_ldap_entries`.
#[cfg(test)]
mod connector_tests;

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
        // The bind DN is a configured distinguished name, used as it is
        // configured: it is not a value to escape.
        let bind_dn = bind_dn_for(config)?;
        let bind_pw = config.bind_password.clone();
        let search_base = resolve_search_base(config);
        let raw_filter = sync
            .user_search_filter
            .as_deref()
            .unwrap_or("(objectClass=user)");
        let sanitized_filter = sanitize_admin_search_filter(raw_filter)?;
        let mapping = mapping.clone();
        let options = search_options(config);

        tokio::task::spawn_blocking(move || {
            run_ldap_search_with_options(
                &url,
                bind_dn,
                bind_pw,
                &search_base,
                &sanitized_filter,
                &mapping,
                options,
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

/// The search options a provider connection asks for. The page size is a
/// requirement on the directory: with a page size the search expects the
/// PagedResults control on every page.
fn search_options(config: &DirectoryConnectionConfig) -> LdapSearchOptions {
    LdapSearchOptions {
        page_size: config.page_size,
        tls_insecure: config.tls_insecure_skip_verify,
        timeout_secs: config.connect_timeout_seconds.unwrap_or(10),
    }
}

/// Parse and re-serialize an LDAP filter with proper value escaping.
/// Delegates to the RFC 4515 parser in `ldap_filter`.
fn sanitize_admin_search_filter(filter: &str) -> QidResult<String> {
    ldap_filter::sanitize_admin_search_filter(filter)
}

pub struct LdapSearchOptions {
    /// Requested RFC 2696 page size. A directory that does not implement
    /// RFC 2696 paging must be read without a page size: with a page size the
    /// search expects the PagedResults control on every page and fails when
    /// the directory does not return it.
    pub page_size: Option<u32>,
    /// Skip the TLS certificate verification. ldap3's flag disables the server
    /// name check as well as the chain check, so it covers the whole connection.
    pub tls_insecure: bool,
    pub timeout_secs: u64,
}

impl Default for LdapSearchOptions {
    fn default() -> Self {
        Self {
            page_size: None,
            tls_insecure: false,
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

/// Run operations with an owned driver. JoinSet aborts the driver on cancellation;
/// unlike ldap3::drive!, this never leaves a detached connection task behind.
/// Callers choose settings: production must continue to require StartTLS or LDAPS.
async fn with_ldap_session<T>(
    settings: ldap3::LdapConnSettings,
    url: &str,
    timeout_secs: u64,
    operation: impl AsyncFnOnce(&mut ldap3::Ldap) -> QidResult<T>,
) -> QidResult<T> {
    use std::time::Duration;

    let (conn, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, url)
        .await
        .map_err(|e| QidError::Internal {
            message: format!("LDAP connect to {url} failed: {e}"),
        })?;
    let mut driver = tokio::task::JoinSet::new();
    driver.spawn(conn.drive());
    // ldap3's operation timeout is one-shot; callers set it before every bind/search.
    // This duration separately bounds session cleanup below.
    let timeout = Duration::from_secs(timeout_secs);
    let result = operation(&mut ldap).await;

    // Always try unbind, including after bind/search errors. Bound cleanup even
    // if the transport cannot send, then drop the last handle to close the driver.
    let unbind = tokio::time::timeout(timeout, ldap.unbind())
        .await
        .map_err(|e| QidError::Internal {
            message: format!("LDAP unbind timed out: {e}"),
        })
        .and_then(|r| {
            r.map_err(|e| QidError::Internal {
                message: format!("LDAP unbind failed: {e}"),
            })
        });
    drop(ldap);
    let closed = match tokio::time::timeout(timeout, driver.join_next()).await {
        Ok(Some(Ok(Ok(())))) => Ok(()),
        other => Err(QidError::Internal {
            message: format!("LDAP connection driver failed to close cleanly: {other:?}"),
        }),
    };
    // Observe both cleanup results, but preserve the original operation error.
    if let Err(error) = &unbind {
        tracing::warn!(%error, "LDAP session cleanup failed");
    }
    if let Err(error) = &closed {
        tracing::warn!(%error, "LDAP driver cleanup failed");
    }
    match result {
        Err(error) => Err(error),
        Ok(value) => unbind.and(closed).map(|()| value),
    }
}

async fn ldap_simple_bind_with_timeout(
    ldap: &mut ldap3::Ldap,
    bind_dn: &str,
    bind_password: &str,
    timeout: std::time::Duration,
) -> QidResult<()> {
    ldap.with_timeout(timeout);
    let result = ldap
        .simple_bind(bind_dn, bind_password)
        .await
        .map_err(|e| QidError::Internal {
            message: format!("LDAP bind failed: {e}"),
        })?;
    ensure_ldap_bind_success(result)
}

async fn ldap_search_with_timeout(
    ldap: &mut ldap3::Ldap,
    base: &str,
    scope: ldap3::Scope,
    filter: &str,
    attributes: Vec<&str>,
    timeout: std::time::Duration,
) -> QidResult<ldap3::SearchResult> {
    ldap.with_timeout(timeout);
    let result = ldap
        .search(base, scope, filter, attributes)
        .await
        .map_err(|e| QidError::Internal {
            message: format!("LDAP search failed: {e}"),
        })?;
    ensure_ldap_search_success(result)
}

fn ensure_ldap_bind_success(result: ldap3::LdapResult) -> QidResult<()> {
    result
        .success()
        .map(|_| ())
        .map_err(|e| QidError::Internal {
            message: format!("LDAP bind returned a non-success protocol result: {e}"),
        })
}

fn ensure_ldap_search_success(result: ldap3::SearchResult) -> QidResult<ldap3::SearchResult> {
    result
        .success()
        .map(|(entries, response)| ldap3::SearchResult(entries, response))
        .map_err(|e| QidError::Internal {
            message: format!("LDAP search returned a non-success protocol result: {e}"),
        })
}

/// The connection settings a directory search uses, shared by both paths.
fn ldap_search_settings(
    url: &str,
    tls_insecure: bool,
) -> QidResult<(ldap3::LdapConnSettings, String)> {
    if !url.starts_with("ldaps://") && !url.starts_with("ldap://") {
        return Err(qid_core::error::QidError::Config {
            message: "LDAP URL must use ldaps:// or ldap:// scheme".to_string(),
        });
    }
    let settings = ldap3::LdapConnSettings::new()
        .set_starttls(url.starts_with("ldap://"))
        .set_no_tls_verify(tls_insecure);
    Ok((settings, url.to_string()))
}

/// Map one search entry into a directory entry with the attribute mapping.
fn map_ldap_search_entry(
    entry: ldap3::ResultEntry,
    mapping: &DirectoryAttributeMapping,
) -> QidResult<LdapDirectoryEntry> {
    let se = ldap3::SearchEntry::construct(entry);
    let mut attrs = std::collections::BTreeMap::new();
    for (k, v) in se.attrs {
        attrs.insert(k, v);
    }
    map_ldap_entry(&se.dn, &attrs, mapping, true)
}

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

/// Evaluate the `enabled` attribute-mapping expression.
///
/// Only the documented Active Directory predicate is supported:
/// `!(userAccountControl:1.2.840.113556.1.4.803:=2)`
/// (LDAP_MATCHING_RULE_BIT_AND for `ACCOUNTDISABLE` = 2).
/// ASCII whitespace is ignored and the attribute name matches
/// case-insensitively. Every other expression — including the
/// non-negated `(userAccountControl:1.2.840.113556.1.4.803:=2)` —
/// is rejected rather than guessed (fail closed).
///
/// For the supported predicate a missing or non-numeric
/// `userAccountControl` value is an error; it must not silently
/// fall back to enabled.
pub fn evaluate_enabled_expression(
    expr: &str,
    user_account_control: Option<&str>,
) -> QidResult<bool> {
    validate_enabled_expression(expr)?;
    let raw = user_account_control.ok_or_else(|| QidError::Internal {
        message: "missing userAccountControl for enabled expression".to_string(),
    })?;
    let flags = raw.trim().parse::<u64>().map_err(|_| QidError::Internal {
        message: "malformed userAccountControl value: expected unsigned integer".to_string(),
    })?;
    // Bit 1 = ACCOUNTDISABLE.
    Ok(flags & 2 == 0)
}

/// Validate a configured `enabled` expression without entry data.
///
/// Accepts only the documented predicate
/// `!(userAccountControl:1.2.840.113556.1.4.803:=2)`
/// (ASCII whitespace ignored, attribute name case-insensitive).
/// Rejects everything else so an empty search result cannot conceal
/// unsupported configuration.
fn validate_enabled_expression(expr: &str) -> QidResult<()> {
    const SUPPORTED_EXPRESSION: &str = "!(userAccountControl:1.2.840.113556.1.4.803:=2)";
    let compact: String = expr.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.eq_ignore_ascii_case(SUPPORTED_EXPRESSION) {
        Ok(())
    } else {
        Err(QidError::BadRequest {
            message: format!(
                "unsupported enabled expression; only `{SUPPORTED_EXPRESSION}` is supported"
            ),
        })
    }
}

/// Map raw LDAP attribute values into a canonical `LdapDirectoryEntry`.
///
/// LDAP attribute descriptions are case-insensitive; ambiguous case-variant
/// duplicates are rejected rather than selecting a value arbitrarily.
pub fn map_ldap_entry(
    dn: &str,
    attrs: &std::collections::BTreeMap<String, Vec<String>>,
    mapping: &DirectoryAttributeMapping,
    default_enabled: bool,
) -> QidResult<LdapDirectoryEntry> {
    let uid_attr = mapping.uid.as_deref().unwrap_or("sAMAccountName");
    let uid = get_first_attr(attrs, uid_attr)?.unwrap_or_else(|| dn.to_string());

    let enabled = if let Some(enabled_expr) = &mapping.enabled {
        let uac = get_first_attr(attrs, "userAccountControl")?;
        evaluate_enabled_expression(enabled_expr, uac.as_deref())?
    } else {
        default_enabled
    };

    Ok(LdapDirectoryEntry {
        dn: dn.to_string(),
        uid,
        mail: get_first_attr(attrs, mapping.mail.as_deref().unwrap_or("mail"))?,
        display_name: get_first_attr(
            attrs,
            mapping.display_name.as_deref().unwrap_or("displayName"),
        )?,
        department: get_first_attr(attrs, mapping.department.as_deref().unwrap_or("department"))?,
        manager_dn: get_first_attr(attrs, mapping.manager_dn.as_deref().unwrap_or("manager"))?,
        enabled,
    })
}

fn get_first_attr(
    attrs: &std::collections::BTreeMap<String, Vec<String>>,
    key: &str,
) -> QidResult<Option<String>> {
    let mut matches = attrs
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(key));
    let Some((_, values)) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(qid_core::error::QidError::Internal {
            message: format!(
                "LDAP entry contains duplicate equivalent attribute descriptions for '{key}'"
            ),
        });
    }
    Ok(values.first().cloned())
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
    if let Some(enabled_expr) = mapping.enabled.as_deref() {
        validate_enabled_expression(enabled_expr)?;
    }
    let (settings, url) = ldap_search_settings(url, options.tls_insecure)?;

    shared_runtime().block_on(async {
        with_ldap_session(settings, &url, options.timeout_secs, async |ldap| {
            let operation_timeout = std::time::Duration::from_secs(options.timeout_secs);
            if let Some((dn, pw)) = bind_credentials(bind_dn.as_deref(), bind_pw.as_deref())? {
                ldap_simple_bind_with_timeout(ldap, dn, pw, operation_timeout).await?;
            }

            let page_size = options.page_size.unwrap_or(0);
            let mut all_entries = Vec::new();
            let mut cookie = Vec::new();
            let mut progress = PagedSearch::new(page_size as usize);

            loop {
                if page_size > 0 {
                    ldap.with_controls(ldap3::controls::PagedResults {
                        size: page_size as i32,
                        cookie: cookie.clone(),
                    });
                }
                let ldap3::SearchResult(entries, res) = ldap_search_with_timeout(
                    ldap,
                    search_base,
                    ldap3::Scope::Subtree,
                    search_filter,
                    vec!["*", "userAccountControl"],
                    operation_timeout,
                )
                .await?;
                if page_size > 0 {
                    cookie = paged_results_cookie(&res.ctrls)?;
                }
                // The bound is checked before the entries are mapped, so a
                // search that outgrows it fails without doing the work.
                progress.record_page(entries.len())?;
                for entry in entries {
                    all_entries.push(map_ldap_search_entry(entry, mapping)?);
                }
                if page_size == 0 || cookie.is_empty() {
                    break;
                }
            }

            Ok(all_entries)
        })
        .await
    })
}

/// The progress of one directory search, against the bounds it must
/// respect.
///
/// The entry ceiling is the product's guarantee: a search collects at most
/// [`MAX_DIRECTORY_SEARCH_ENTRIES`] entries, which is above the size of the
/// directories the supported servers are documented to hold. The pages a
/// search may fetch follow from the entry ceiling and the requested page
/// size, so a directory that keeps handing back a paging cookie fails the
/// sync with a clear error instead of looping forever, and a small page
/// size does not shrink what a directory may hold.
struct PagedSearch {
    pages: usize,
    entries: usize,
    max_pages: usize,
    max_entries: usize,
}

impl PagedSearch {
    /// The bounds for a search that requests `page_size` entries per page.
    fn new(page_size: usize) -> Self {
        let max_entries = MAX_DIRECTORY_SEARCH_ENTRIES as usize;
        // A search without paging fetches one page, so the page bound is
        // one; a paged search may fetch the pages the entry ceiling allows
        // at the requested page size.
        let max_pages = if page_size == 0 {
            1
        } else {
            max_entries.div_ceil(page_size)
        };
        Self {
            pages: 0,
            entries: 0,
            max_pages,
            max_entries,
        }
    }

    /// Record one fetched page of `entries` entries.
    fn record_page(&mut self, entries: usize) -> QidResult<()> {
        self.pages += 1;
        if self.pages > self.max_pages {
            return Err(QidError::Internal {
                message: format!(
                    "LDAP paged search fetched more than {} pages",
                    self.max_pages
                ),
            });
        }
        self.entries += entries;
        if self.entries > self.max_entries {
            return Err(QidError::Internal {
                message: format!(
                    "LDAP paged search returned more than {} entries",
                    self.max_entries
                ),
            });
        }
        Ok(())
    }
}

/// The cookie of the next page, taken from the PagedResults control the
/// server must return for every requested page. A missing control is an
/// error: reusing the previous cookie would repeat a page, and ending the
/// search would truncate the result silently.
pub(crate) fn paged_results_cookie(ctrls: &[ldap3::controls::Control]) -> QidResult<Vec<u8>> {
    use ldap3::controls::{Control, ControlType, PagedResults};
    let raw = ctrls.iter().find_map(|ctrl| {
        if let Control(Some(ControlType::PagedResults), raw) = ctrl {
            Some(raw)
        } else {
            None
        }
    });
    let Some(raw) = raw else {
        return Err(QidError::Internal {
            message: "LDAP paged search did not return a PagedResults control".to_string(),
        });
    };
    // A PagedResults control value is a BER sequence, and the ldap3 parser
    // panics on a missing value or on a value that is not a sequence, so both
    // are rejected before the parse.
    let Some(value) = raw.val.as_deref() else {
        return Err(QidError::Internal {
            message: "LDAP paged search returned an unusable PagedResults control".to_string(),
        });
    };
    if value.first() != Some(&0x30) {
        return Err(QidError::Internal {
            message: "LDAP paged search returned an unusable PagedResults control".to_string(),
        });
    }
    // The remaining parse is contained, and the panic hook is silenced while it
    // runs, so an unusable control produces an error and no panic output. The
    // hook is process-wide, so the swap is serialized: a second caller must
    // not restore the silent hook.
    static PANIC_HOOK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = PANIC_HOOK.lock().unwrap_or_else(|error| error.into_inner());
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let parsed = std::panic::catch_unwind(|| raw.parse::<PagedResults>());
    std::panic::set_hook(previous);
    let Ok(pr) = parsed else {
        return Err(QidError::Internal {
            message: "LDAP paged search returned an unusable PagedResults control".to_string(),
        });
    };
    Ok(pr.cookie)
}

#[cfg(test)]
mod tests {
    use super::connector_tests::TestDirectoryConnector;
    use super::*;

    #[test]
    fn resolves_base_dn_from_url() {
        let config = DirectoryConnectionConfig {
            page_size: None,
            url: "ldaps://ad.example.com:636".to_string(),
            ..Default::default()
        };
        assert_eq!(resolve_search_base(&config), "dc=ad,dc=example,dc=com");
    }

    #[test]
    fn uses_explicit_base_dn() {
        let config = DirectoryConnectionConfig {
            page_size: None,
            url: "ldaps://ad.example.com:636".to_string(),
            base_dn: Some("dc=custom,dc=com".to_string()),
            ..Default::default()
        };
        assert_eq!(resolve_search_base(&config), "dc=custom,dc=com");
    }

    #[test]
    fn returns_empty_when_no_ldap_url() {
        let config = DirectoryConnectionConfig {
            page_size: None,
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
        attrs.insert("userAccountControl".to_string(), vec!["512".to_string()]);

        let mapping = DirectoryAttributeMapping::default();
        let entry = map_ldap_entry(
            "CN=Alice,OU=Users,DC=example,DC=com",
            &attrs,
            &mapping,
            true,
        )
        .unwrap();

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
    fn maps_ldap_attribute_descriptions_case_insensitively() {
        let attrs = std::collections::BTreeMap::from([
            ("SAMACCOUNTNAME".to_string(), vec!["alice".to_string()]),
            ("MAIL".to_string(), vec!["alice@example.com".to_string()]),
            ("DISPLAYNAME".to_string(), vec!["Alice Example".to_string()]),
            ("DEPARTMENT".to_string(), vec!["Engineering".to_string()]),
            (
                "MANAGER".to_string(),
                vec!["CN=Bob,OU=Users,DC=example,DC=com".to_string()],
            ),
            ("USERACCOUNTCONTROL".to_string(), vec!["514".to_string()]),
        ]);

        let entry = map_ldap_entry(
            "CN=Alice,OU=Users,DC=example,DC=com",
            &attrs,
            &DirectoryAttributeMapping::default(),
            true,
        )
        .unwrap();

        assert_eq!(entry.uid, "alice");
        assert_eq!(entry.mail.as_deref(), Some("alice@example.com"));
        assert_eq!(entry.display_name.as_deref(), Some("Alice Example"));
        assert_eq!(entry.department.as_deref(), Some("Engineering"));
        assert_eq!(
            entry.manager_dn.as_deref(),
            Some("CN=Bob,OU=Users,DC=example,DC=com")
        );
        assert!(!entry.enabled);
    }

    #[test]
    fn rejects_duplicate_case_insensitive_ldap_attribute_descriptions() {
        let attrs = std::collections::BTreeMap::from([
            ("sAMAccountName".to_string(), vec!["alice".to_string()]),
            ("SAMACCOUNTNAME".to_string(), vec!["mallory".to_string()]),
        ]);
        let error = map_ldap_entry(
            "CN=Alice,OU=Users,DC=example,DC=com",
            &attrs,
            &DirectoryAttributeMapping::default(),
            true,
        )
        .unwrap_err();
        assert!(
            error
                .message()
                .contains("duplicate equivalent attribute descriptions")
        );
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
        )
        .unwrap();

        assert!(!entry.enabled);
        assert_eq!(entry.uid, "disabled-user");
    }

    #[test]
    fn missing_user_account_control_is_an_error() {
        let attrs = std::collections::BTreeMap::new();

        let mapping = DirectoryAttributeMapping::default();
        let error = map_ldap_entry(
            "CN=No UAC,OU=Users,DC=example,DC=com",
            &attrs,
            &mapping,
            true,
        )
        .unwrap_err();

        assert!(error.message().contains("missing userAccountControl"));
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
            enabled: None,
            ..Default::default()
        };

        let entry =
            map_ldap_entry("CN=Bob,OU=Users,DC=example,DC=com", &attrs, &mapping, true).unwrap();

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
        assert!(
            evaluate_enabled_expression(
                "!(userAccountControl:1.2.840.113556.1.4.803:=2)",
                Some("512")
            )
            .unwrap()
        );
    }

    #[test]
    fn evaluate_enabled_false_for_disabled_account() {
        assert!(
            !evaluate_enabled_expression(
                "!(userAccountControl:1.2.840.113556.1.4.803:=2)",
                Some("514")
            )
            .unwrap()
        );
    }

    #[test]
    fn evaluate_enabled_accepts_whitespace_and_case_variation() {
        assert!(
            evaluate_enabled_expression(
                "! (USERACCOUNTCONTROL : 1.2.840.113556.1.4.803 := 2)",
                Some("512")
            )
            .unwrap()
        );
        assert!(
            !evaluate_enabled_expression(
                "! (USERACCOUNTCONTROL : 1.2.840.113556.1.4.803 := 2)",
                Some("514")
            )
            .unwrap()
        );
    }

    #[test]
    fn evaluate_enabled_rejects_inverse_predicate() {
        let error = evaluate_enabled_expression(
            "(userAccountControl:1.2.840.113556.1.4.803:=2)",
            Some("512"),
        )
        .unwrap_err();
        assert!(error.message().contains("unsupported enabled expression"));
    }

    #[test]
    fn evaluate_enabled_rejects_unrelated_expression() {
        let error = evaluate_enabled_expression("(objectClass=user)", Some("512")).unwrap_err();
        assert!(error.message().contains("unsupported enabled expression"));
    }

    #[test]
    fn evaluate_enabled_rejects_missing_user_account_control() {
        let error =
            evaluate_enabled_expression("!(userAccountControl:1.2.840.113556.1.4.803:=2)", None)
                .unwrap_err();
        assert!(error.message().contains("missing userAccountControl"));
    }

    #[test]
    fn evaluate_enabled_rejects_malformed_user_account_control() {
        let error = evaluate_enabled_expression(
            "!(userAccountControl:1.2.840.113556.1.4.803:=2)",
            Some("not-a-number"),
        )
        .unwrap_err();
        assert!(error.message().contains("malformed userAccountControl"));
    }

    #[test]
    fn map_ldap_entry_rejects_unsupported_enabled_expression() {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("sAMAccountName".to_string(), vec!["alice".to_string()]);
        attrs.insert("userAccountControl".to_string(), vec!["512".to_string()]);
        let mapping = DirectoryAttributeMapping {
            enabled: Some("(userAccountControl:1.2.840.113556.1.4.803:=2)".to_string()),
            ..Default::default()
        };
        let error = map_ldap_entry(
            "CN=Alice,OU=Users,DC=example,DC=com",
            &attrs,
            &mapping,
            true,
        )
        .unwrap_err();
        assert!(error.message().contains("unsupported enabled expression"));
    }

    #[test]
    fn map_ldap_entry_rejects_malformed_user_account_control() {
        let attrs = std::collections::BTreeMap::from([
            ("sAMAccountName".to_string(), vec!["alice".to_string()]),
            ("userAccountControl".to_string(), vec!["bogus".to_string()]),
        ]);
        let error = map_ldap_entry(
            "CN=Alice,OU=Users,DC=example,DC=com",
            &attrs,
            &DirectoryAttributeMapping::default(),
            true,
        )
        .unwrap_err();
        assert!(error.message().contains("malformed userAccountControl"));
    }

    #[test]
    fn the_ldap_search_rejects_an_unsupported_enabled_expression_before_connecting() {
        let mapping = DirectoryAttributeMapping {
            enabled: Some("(userAccountControl:1.2.840.113556.1.4.803:=2)".to_string()),
            ..Default::default()
        };

        let error = run_ldap_search_with_options(
            "not-an-ldap-url",
            None,
            None,
            "dc=example,dc=com",
            "(objectClass=user)",
            &mapping,
            LdapSearchOptions::default(),
        )
        .unwrap_err();
        assert!(error.message().contains("unsupported enabled expression"));
    }

    #[test]
    fn validate_enabled_expression_rejects_unsupported_upfront() {
        let error = validate_enabled_expression("(objectClass=user)").unwrap_err();
        assert!(error.message().contains("unsupported enabled expression"));
        validate_enabled_expression("!(userAccountControl:1.2.840.113556.1.4.803:=2)").unwrap();
    }

    #[test]
    fn ldap_search_options_default() {
        let opts = LdapSearchOptions::default();
        assert_eq!(opts.page_size, None);
    }
}

#[cfg(test)]
mod driver_tests;
