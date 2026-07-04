use super::*;

#[test]
fn admin_reason_requires_non_empty_header() {
    let headers = HeaderMap::new();
    assert!(matches!(
        admin_reason(&headers),
        Err(QidError::BadRequest { .. })
    ));

    let mut headers = HeaderMap::new();
    headers.insert(ADMIN_REASON_HEADER, "  ticket-123  ".parse().unwrap());
    assert_eq!(admin_reason(&headers).unwrap(), "ticket-123");
}
fn stepped_up_headers(roles: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let security = AdminSecurityConfig::default();
    headers.insert(ADMIN_ROLES_HEADER, roles.parse().unwrap());
    headers.insert(ADMIN_ACR_HEADER, security.required_acr.parse().unwrap());
    headers.insert(ADMIN_AMR_HEADER, "pwd,hwk".parse().unwrap());
    headers.insert(
        ADMIN_ELEVATION_EXPIRES_AT_HEADER,
        (qid_core::util::now_seconds() + 60)
            .to_string()
            .parse()
            .unwrap(),
    );
    headers
}

#[test]
fn admin_authorization_requires_step_up_and_role() {
    let security = AdminSecurityConfig::default();
    let headers = HeaderMap::new();
    assert!(matches!(
        authorize_admin_headers(&headers, AdminPermission::AppAdmin, &security),
        Err(QidError::Unauthorized { .. })
    ));

    let headers = stepped_up_headers("auditor");
    assert!(matches!(
        authorize_admin_headers(&headers, AdminPermission::AppAdmin, &security),
        Err(QidError::Unauthorized { .. })
    ));

    let headers = stepped_up_headers("app.admin");
    assert!(authorize_admin_headers(&headers, AdminPermission::AppAdmin, &security).is_ok());

    let headers = stepped_up_headers("tenant.owner");
    assert!(authorize_admin_headers(&headers, AdminPermission::TenantAdmin, &security).is_ok());
    assert!(authorize_admin_headers(&headers, AdminPermission::DirectoryAdmin, &security).is_err());
    assert!(authorize_admin_headers(&headers, AdminPermission::BreakGlass, &security).is_err());

    let headers = stepped_up_headers("breakglass");
    assert!(authorize_admin_headers(&headers, AdminPermission::BreakGlass, &security).is_ok());
}

#[test]
fn audit_limit_is_bounded() {
    assert_eq!(audit_limit(None), 100);
    assert_eq!(audit_limit(Some(0)), 1);
    assert_eq!(audit_limit(Some(42)), 42);
    assert_eq!(audit_limit(Some(1000)), 500);
}

#[test]
fn audit_export_options_default_to_metadata() {
    let query = AuditQuery {
        limit: None,
        traceparent: Some("trace".to_string()),
        audit_correlation_id: Some("corr".to_string()),
        include_metadata: None,
    };
    let options = audit_export_options(&query);
    assert!(options.include_metadata);
    assert_eq!(options.traceparent.as_deref(), Some("trace"));
    assert_eq!(options.audit_correlation_id.as_deref(), Some("corr"));
}
