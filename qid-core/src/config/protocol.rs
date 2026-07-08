use super::*;

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtocolConfig {
    #[serde(default)]
    pub oidc: OidcProtocolConfig,
    #[serde(default)]
    pub oauth: OAuthProtocolConfig,
    #[serde(default)]
    pub saml: SamlProtocolConfig,
    #[serde(default)]
    pub scim: ScimProtocolConfig,
    #[serde(default)]
    pub fedcm: FedCmProtocolConfig,
    #[serde(default)]
    pub federation: FederationProtocolConfig,
    #[serde(default)]
    pub directory: DirectoryConfig,
    #[serde(default)]
    pub ciam: CiamProtocolConfig,
    #[serde(default)]
    pub vc: VcProtocolConfig,
    #[serde(default)]
    pub workload: WorkloadProtocolConfig,
    #[serde(default)]
    pub network_aaa: NetworkAaaProtocolConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcProtocolConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub authorization_code: OidcAuthorizationCodeConfig,
    #[serde(default)]
    pub implicit: ProtocolFeatureConfig,
    #[serde(default)]
    pub ropc: ProtocolFeatureConfig,
    #[serde(default = "default_true")]
    pub discovery: bool,
    #[serde(default = "default_true")]
    pub userinfo: bool,
    #[serde(default)]
    pub logout: OidcLogoutConfig,
    #[serde(default = "default_oidc_scope")]
    pub default_scope: String,
    #[serde(default)]
    pub session_management: bool,
}

impl Default for OidcProtocolConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            authorization_code: OidcAuthorizationCodeConfig::default(),
            implicit: ProtocolFeatureConfig::default(),
            ropc: ProtocolFeatureConfig::default(),
            discovery: default_true(),
            userinfo: default_true(),
            logout: OidcLogoutConfig::default(),
            default_scope: default_oidc_scope(),
            session_management: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcAuthorizationCodeConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub pkce_required: bool,
    /// FAPI 2.0 Security Profile §5.2.3: when true, the authorization
    /// endpoint MUST receive the request parameters inside a signed request
    /// object (JAR, RFC 9101). Unsigned authorization requests are rejected.
    #[serde(default)]
    pub require_signed_request_object: bool,
    /// Algorithms that are accepted when verifying the JAR signature. The
    /// metadata advertises these under
    /// `request_object_signing_alg_values_supported`.
    #[serde(default = "default_request_object_alg_values")]
    pub request_object_signing_alg_values: Vec<String>,
}

impl Default for OidcAuthorizationCodeConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            pkce_required: default_true(),
            require_signed_request_object: false,
            request_object_signing_alg_values: default_request_object_alg_values(),
        }
    }
}

fn default_request_object_alg_values() -> Vec<String> {
    vec![
        "ES256".to_string(),
        "EdDSA".to_string(),
        "RS256".to_string(),
    ]
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcLogoutConfig {
    #[serde(default = "default_true")]
    pub backchannel: bool,
    #[serde(default = "default_true")]
    pub frontchannel: bool,
}

impl Default for OidcLogoutConfig {
    fn default() -> Self {
        Self {
            backchannel: default_true(),
            frontchannel: default_true(),
        }
    }
}

fn default_oidc_scope() -> String {
    "openid".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OAuthProtocolConfig {
    #[serde(default)]
    pub introspection: IntrospectionConfig,
    #[serde(default)]
    pub revocation: RevocationConfig,
    #[serde(default)]
    pub par: ParConfig,
    #[serde(default)]
    pub rar: ProtocolFeatureConfig,
    #[serde(default)]
    pub dpop: DpopProtocolConfig,
    #[serde(default)]
    pub mtls: ProtocolFeatureConfig,
    #[serde(default)]
    pub device_authorization: ProtocolFeatureConfig,
    #[serde(default)]
    pub ciba: CibaConfig,
    #[serde(default)]
    pub dynamic_client_registration: ProtocolFeatureConfig,
    #[serde(default)]
    pub private_key_jwt: ProtocolFeatureConfig,
    #[serde(default)]
    pub jarm: ProtocolFeatureConfig,
    #[serde(default = "default_oauth_scope")]
    pub default_scope: String,
    #[serde(default)]
    pub tokens: TokenTtlConfig,
    #[serde(default)]
    pub resource_servers: Vec<OAuthResourceServerConfig>,
    /// When true, authorization endpoint requires pushed authorization requests (PAR).
    /// Per FAPI 2.0 Security Profile §5.2.2.
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
}

impl Default for OAuthProtocolConfig {
    fn default() -> Self {
        Self {
            introspection: IntrospectionConfig::default(),
            revocation: RevocationConfig::default(),
            par: ParConfig::default(),
            rar: ProtocolFeatureConfig::default(),
            dpop: DpopProtocolConfig::default(),
            mtls: ProtocolFeatureConfig::default(),
            device_authorization: ProtocolFeatureConfig::default(),
            ciba: CibaConfig::default(),
            dynamic_client_registration: ProtocolFeatureConfig::default(),
            private_key_jwt: ProtocolFeatureConfig::default(),
            jarm: ProtocolFeatureConfig::default(),
            default_scope: default_oauth_scope(),
            tokens: TokenTtlConfig::default(),
            resource_servers: Vec::new(),
            require_pushed_authorization_requests: false,
        }
    }
}

fn default_oauth_scope() -> String {
    "api".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OAuthResourceServerConfig {
    pub audience: String,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub introspection_client_ids: Vec<String>,
    #[serde(default)]
    pub require_sender_constraint: bool,
    #[serde(default)]
    pub high_risk: bool,
}

impl OAuthResourceServerConfig {
    pub(crate) fn validate(&self, realm_id: &str) -> QidResult<()> {
        if self.audience.trim().is_empty() {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} OAuth resource server audience must not be empty"
                ),
            });
        }
        let mut seen_resources = std::collections::HashSet::new();
        for resource in &self.resources {
            if resource.trim().is_empty() {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} OAuth resource server {} has an empty resource indicator",
                        self.audience
                    ),
                });
            }
            if !seen_resources.insert(resource) {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} OAuth resource server {} has duplicate resource indicator {resource}",
                        self.audience
                    ),
                });
            }
        }
        for scope in &self.scopes {
            if scope.trim().is_empty() {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} OAuth resource server {} has an empty scope",
                        self.audience
                    ),
                });
            }
        }
        let mut seen_clients = std::collections::HashSet::new();
        for client_id in &self.introspection_client_ids {
            if client_id.trim().is_empty() {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} OAuth resource server {} has an empty introspection client id",
                        self.audience
                    ),
                });
            }
            if !seen_clients.insert(client_id) {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} OAuth resource server {} has duplicate introspection client id {client_id}",
                        self.audience
                    ),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtocolFeatureConfig {
    pub enabled: bool,
    /// Allow dynamic client registration without an initial access token.
    /// Default: `false` (fail closed).
    pub allow_open_registration: bool,
}

impl ProtocolFeatureConfig {
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            allow_open_registration: false,
        }
    }
}

impl<'de> Deserialize<'de> for ProtocolFeatureConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Bool(bool),
            Object {
                #[serde(default)]
                enabled: bool,
                #[serde(default)]
                allow_open_registration: bool,
            },
        }

        match Wire::deserialize(deserializer)? {
            Wire::Bool(enabled) => Ok(Self {
                enabled,
                allow_open_registration: false,
            }),
            Wire::Object {
                enabled,
                allow_open_registration,
            } => Ok(Self {
                enabled,
                allow_open_registration,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CibaMode {
    #[default]
    Poll,
    Ping,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CibaConfig {
    pub enabled: bool,
    pub mode: CibaMode,
}

impl Default for CibaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: CibaMode::Poll,
        }
    }
}

impl<'de> Deserialize<'de> for CibaConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Bool(bool),
            Object {
                #[serde(default)]
                enabled: bool,
                #[serde(default)]
                mode: CibaMode,
            },
        }

        match Wire::deserialize(deserializer)? {
            Wire::Bool(enabled) => Ok(Self {
                enabled,
                mode: CibaMode::Poll,
            }),
            Wire::Object { enabled, mode } => Ok(Self { enabled, mode }),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParConfig {
    pub enabled: bool,
    pub required_for: Vec<String>,
}

impl<'de> Deserialize<'de> for ParConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Bool(bool),
            Object {
                #[serde(default)]
                enabled: bool,
                #[serde(default)]
                required_for: Vec<String>,
            },
        }

        match Wire::deserialize(deserializer)? {
            Wire::Bool(enabled) => Ok(Self {
                enabled,
                required_for: Vec::new(),
            }),
            Wire::Object {
                enabled,
                required_for,
            } => Ok(Self {
                enabled,
                required_for,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectionConfig {
    pub enabled: bool,
    pub jwt_response: bool,
}

impl Default for IntrospectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            jwt_response: false,
        }
    }
}

impl<'de> Deserialize<'de> for IntrospectionConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Bool(bool),
            Object {
                #[serde(default)]
                enabled: bool,
                #[serde(default)]
                jwt_response: bool,
            },
        }

        match Wire::deserialize(deserializer)? {
            Wire::Bool(enabled) => Ok(Self {
                enabled,
                jwt_response: false,
            }),
            Wire::Object {
                enabled,
                jwt_response,
            } => Ok(Self {
                enabled,
                jwt_response,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopProtocolConfig {
    pub enabled: bool,
    pub replay_cache: bool,
    pub nonce: bool,
}

impl Default for DpopProtocolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            replay_cache: true,
            nonce: false,
        }
    }
}

impl<'de> Deserialize<'de> for DpopProtocolConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Bool(bool),
            Object {
                #[serde(default)]
                enabled: bool,
                #[serde(default = "default_true")]
                replay_cache: bool,
                #[serde(default)]
                nonce: bool,
            },
        }

        match Wire::deserialize(deserializer)? {
            Wire::Bool(enabled) => Ok(Self {
                enabled,
                replay_cache: true,
                nonce: false,
            }),
            Wire::Object {
                enabled,
                replay_cache,
                nonce,
            } => Ok(Self {
                enabled,
                replay_cache,
                nonce,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationConfig {
    pub enabled: bool,
    pub webhook_url: Option<String>,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            webhook_url: None,
        }
    }
}

impl<'de> Deserialize<'de> for RevocationConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Bool(bool),
            Object {
                #[serde(default = "default_true")]
                enabled: bool,
                #[serde(default)]
                webhook_url: Option<String>,
            },
        }

        match Wire::deserialize(deserializer)? {
            Wire::Bool(enabled) => Ok(Self {
                enabled,
                webhook_url: None,
            }),
            Wire::Object {
                enabled,
                webhook_url,
            } => Ok(Self {
                enabled,
                webhook_url,
            }),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SamlProtocolConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub sign_assertions: bool,
    #[serde(default)]
    pub encrypt_assertions: Option<String>,
    /// Maximum clock skew in seconds for SAML assertion validation.
    /// Applied to Conditions NotBefore / NotOnOrAfter and
    /// SubjectConfirmationData NotOnOrAfter.
    /// Default: 60 (OASIS SAML 2.0 profile recommendation).
    #[serde(default = "default_saml_clock_skew")]
    pub max_clock_skew_seconds: u64,
    /// Whether to include a W3C XMLDSig signature in the IdP metadata.
    /// Requires `idp_signing_key_pem_path`.
    #[serde(default)]
    pub sign_metadata: bool,
    /// Path to a PKCS#8 PEM private key used to produce W3C XMLDSig
    /// signatures on SAML Responses, Assertions, and the IdP metadata
    /// document. Required when SAML response/assertion signing or
    /// metadata signing is enabled.
    #[serde(default)]
    pub idp_signing_key_pem_path: Option<String>,
    /// Path to a PKCS#8 PEM private key used to decrypt incoming
    /// `<saml:EncryptedAssertion>` elements in the SAML bearer grant
    /// flow (RFC 7522). When set, the IdP will use this key to decrypt
    /// encrypted assertions submitted via
    /// `urn:ietf:params:oauth:grant-type:saml2-bearer`.
    #[serde(default)]
    pub idp_encryption_key_pem_path: Option<String>,
    #[serde(default)]
    pub service_providers: Vec<SamlServiceProviderConfig>,
}

fn default_saml_clock_skew() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SamlServiceProviderConfig {
    pub entity_id: String,
    pub acs_url: String,
    #[serde(default)]
    pub slo_url: Option<String>,
    #[serde(default)]
    pub name_id_formats: Vec<String>,
    #[serde(default)]
    pub attribute_release_policy: Vec<String>,
    #[serde(default)]
    pub signing_certificates: Vec<String>,
    #[serde(default)]
    pub encryption_certificates: Vec<String>,
    #[serde(default)]
    pub want_assertions_signed: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScimProtocolConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_scim_base_path")]
    pub base_path: String,
    #[serde(default)]
    pub cursor_secret: Option<String>,
    /// Host allowlist for SCIM EventSubscription callback URLs.
    ///
    /// Entries are host names only. Exact hosts are matched literally and
    /// wildcard entries must be of the form `*.example.com`.
    #[serde(default)]
    pub event_callback_allowed_hosts: Vec<String>,
    /// Custom SCIM attribute schemas beyond core User/Group and Enterprise User.
    /// Each entry defines a schema extension that the /Schemas endpoint will include.
    #[serde(default)]
    pub custom_schemas: Vec<CustomScimSchemaConfig>,
}

impl Default for ScimProtocolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_path: default_scim_base_path(),
            cursor_secret: None,
            event_callback_allowed_hosts: Vec::new(),
            custom_schemas: Vec::new(),
        }
    }
}

fn default_scim_base_path() -> String {
    "/scim/v2".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustomScimSchemaConfig {
    /// The schema URN, e.g. "urn:ietf:params:scim:schemas:extension:custom:2.0:Profile"
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Brief description.
    pub description: String,
    /// Attribute definitions following SCIM 2.0 attribute format.
    #[serde(default)]
    pub attributes: Vec<CustomScimAttributeConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustomScimAttributeConfig {
    pub name: String,
    #[serde(default = "default_scim_attr_type")]
    pub r#type: String,
    #[serde(default)]
    pub multi_valued: bool,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub case_exact: bool,
    #[serde(default)]
    pub mutability: String,
    #[serde(default)]
    pub returned: String,
}

fn default_scim_attr_type() -> String {
    "string".to_string()
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FedCmProtocolConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CiamProtocolConfig {
    #[serde(default)]
    pub consent: bool,
    #[serde(default)]
    pub progressive_profile: bool,
    #[serde(default)]
    pub identity_proofing: bool,
    #[serde(default)]
    pub privacy_dashboard: bool,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VcProtocolConfig {
    #[serde(default)]
    pub oid4vci: bool,
    #[serde(default)]
    pub oid4vp: bool,
    #[serde(default)]
    pub haip: bool,
    #[serde(default)]
    pub vc_data_model_2_0: bool,
    #[serde(default)]
    pub jose_cose: bool,
    #[serde(default)]
    pub status_list: bool,
    #[serde(default)]
    pub holder_binding_required: bool,
    #[serde(default)]
    pub issuer_key_ref: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadProtocolConfig {
    #[serde(default)]
    pub spiffe_workload_api: bool,
    #[serde(default)]
    pub x509_svid: bool,
    #[serde(default)]
    pub jwt_svid: bool,
    #[serde(default)]
    pub short_lived_credentials: bool,
    #[serde(default)]
    pub rats_eat: bool,
    #[serde(default)]
    pub token_exchange: bool,
    #[serde(default)]
    pub workload_ca_key_ref: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkAaaProtocolConfig {
    #[serde(default)]
    pub radius: bool,
    #[serde(default)]
    pub radius_authentication_bind: Option<String>,
    #[serde(default)]
    pub radius_tls: bool,
    #[serde(default)]
    pub radius_tls_bind: Option<String>,
    #[serde(default)]
    pub radius_tls_certificate_path: Option<String>,
    #[serde(default)]
    pub radius_tls_private_key_path: Option<String>,
    #[serde(default)]
    pub radius_tls_client_ca_path: Option<String>,
    #[serde(default)]
    pub eap: bool,
    #[serde(default)]
    pub eap_tls: bool,
    #[serde(default)]
    pub capport: bool,
    #[serde(default)]
    pub coa: bool,
    #[serde(default)]
    pub coa_bind: Option<String>,
    #[serde(default)]
    pub accounting: bool,
    #[serde(default)]
    pub accounting_bind: Option<String>,
    #[serde(default)]
    pub directory_authority: bool,
    #[serde(default)]
    pub shared_secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FederationProtocolConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub inbound_providers: Vec<InboundProviderConfig>,
}

/// Configures an inbound identity provider (OIDC, SAML, Social, etc).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InboundProviderConfig {
    pub id: String,
    pub kind: String,
    pub issuer: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub social_provider: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub token_url: Option<String>,
    #[serde(default)]
    pub userinfo_url: Option<String>,
    #[serde(default)]
    pub jit_provisioning: bool,
    #[serde(default)]
    pub account_linking: bool,
    #[serde(default)]
    pub claim_mappings: Vec<ClaimMappingConfig>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    #[serde(default)]
    pub saml_signing_certificates: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimMappingConfig {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectoryConfig {
    /// When true, the directory provider list below is treated as the
    /// default AD/LDAP source. Without setting this and providing at
    /// least one `providers` entry, the worker falls back to the
    /// in-memory `TestDirectoryConnector` which is only useful in
    /// tests. INTEROP §3 requires that directory sync be on by default
    /// for enterprise deployments.
    #[serde(default = "default_directory_enabled")]
    pub enabled: bool,
    /// Identifier of the provider to use when `default_provider_id`
    /// is not set explicitly. This makes directory sync "just work"
    /// for the common case of a single AD/LDAP provider per realm.
    #[serde(default)]
    pub default_provider_id: Option<String>,
    #[serde(default)]
    pub providers: Vec<DirectoryProviderConfig>,
    #[serde(default)]
    pub hr_connectors: Vec<HrConnectorConfig>,
}

fn default_directory_enabled() -> bool {
    true
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_provider_id: None,
            providers: Vec::new(),
            hr_connectors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HrConnectorConfig {
    Csv { file_path: String },
    Webhook { url: String, secret: String },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectoryProviderConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub connection: DirectoryConnectionConfig,
    #[serde(default)]
    pub sync: DirectorySyncConfig,
    #[serde(default)]
    pub attribute_mapping: DirectoryAttributeMapping,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectoryConnectionConfig {
    pub url: String,
    #[serde(default)]
    pub bind_dn: Option<String>,
    #[serde(default)]
    pub bind_password: Option<String>,
    #[serde(default)]
    pub base_dn: Option<String>,
    #[serde(default)]
    pub connect_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub tls_insecure_skip_verify: bool,
}

impl Default for DirectoryConnectionConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            bind_dn: None,
            bind_password: None,
            base_dn: None,
            connect_timeout_seconds: Some(10),
            tls_insecure_skip_verify: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectorySyncConfig {
    #[serde(default)]
    pub user_search_filter: Option<String>,
    #[serde(default)]
    pub group_search_filter: Option<String>,
    #[serde(default)]
    pub sync_interval_minutes: Option<u64>,
    #[serde(default)]
    pub deactivate_missing: bool,
    #[serde(default)]
    pub full_sync_on_start: bool,
}

impl Default for DirectorySyncConfig {
    fn default() -> Self {
        Self {
            user_search_filter: Some("(objectClass=user)".to_string()),
            group_search_filter: None,
            sync_interval_minutes: Some(60),
            deactivate_missing: true,
            full_sync_on_start: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectoryAttributeMapping {
    #[serde(default)]
    pub uid: Option<String>,
    #[serde(default)]
    pub mail: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub manager_dn: Option<String>,
    #[serde(default)]
    pub enabled: Option<String>,
}

impl Default for DirectoryAttributeMapping {
    fn default() -> Self {
        Self {
            uid: Some("sAMAccountName".to_string()),
            mail: Some("mail".to_string()),
            display_name: Some("displayName".to_string()),
            department: Some("department".to_string()),
            manager_dn: Some("manager".to_string()),
            enabled: Some("!(userAccountControl:1.2.840.113556.1.4.803:=2)".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryProviderStatus {
    Disconnected,
    Connected,
    Syncing,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryProviderState {
    pub provider_id: String,
    pub status: DirectoryProviderStatus,
    pub last_sync_at: Option<u64>,
    pub last_sync_result: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TokenTtlConfig {
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl_seconds: u64,
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl_seconds: u64,
    #[serde(default = "default_id_token_ttl")]
    pub id_token_ttl_seconds: u64,
    #[serde(default = "default_auth_code_ttl")]
    pub auth_code_ttl_seconds: u64,
    #[serde(default = "default_par_request_ttl")]
    pub par_request_ttl_seconds: u64,
    #[serde(default = "default_device_code_ttl")]
    pub device_code_ttl_seconds: u64,
    #[serde(default = "default_access_token_format")]
    pub access_token_format: TokenFormat,
}

impl Default for TokenTtlConfig {
    fn default() -> Self {
        Self {
            access_token_ttl_seconds: default_access_token_ttl(),
            refresh_token_ttl_seconds: default_refresh_token_ttl(),
            id_token_ttl_seconds: default_id_token_ttl(),
            auth_code_ttl_seconds: default_auth_code_ttl(),
            par_request_ttl_seconds: default_par_request_ttl(),
            device_code_ttl_seconds: default_device_code_ttl(),
            access_token_format: default_access_token_format(),
        }
    }
}

fn default_access_token_ttl() -> u64 {
    3600
}
fn default_refresh_token_ttl() -> u64 {
    86400
}
fn default_id_token_ttl() -> u64 {
    3600
}
fn default_auth_code_ttl() -> u64 {
    300
}
fn default_par_request_ttl() -> u64 {
    300
}
fn default_device_code_ttl() -> u64 {
    1800
}
fn default_access_token_format() -> TokenFormat {
    TokenFormat::Jwt
}
