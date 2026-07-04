use super::*;

pub(crate) async fn list_realms<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::RealmAdmin,
        &state.config.admin.security,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.list_realms().await {
        Ok(realms) => {
            let items: Vec<serde_json::Value> = realms
                .into_iter()
                .map(|(id, issuer)| serde_json::json!({ "id": id, "issuer": issuer }))
                .collect();
            (StatusCode::OK, Json(serde_json::json!(items))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateRealmRequest {
    id: String,
    issuer: String,
    display_name: Option<String>,
}

pub(crate) async fn create_realm<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<CreateRealmRequest>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::RealmAdmin,
        &state.config.admin.security,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let realm_id = RealmId(req.id.clone());
    match state
        .repo
        .create_realm(
            &TenantId::from(_admin.tenant_id.clone()),
            &realm_id,
            &req.issuer,
            req.display_name.as_deref(),
        )
        .await
    {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(req.id.clone()),
                "realm.create",
                "realm",
                &req.id,
                serde_json::json!({ "issuer": req.issuer, "display_name": req.display_name }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "id": req.id, "issuer": req.issuer })),
            )
                .into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn get_realm<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::RealmAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.get_realm_issuer(&RealmId(realm.clone())).await {
        Ok(Some(issuer)) => {
            let display_name = state
                .config
                .realms
                .iter()
                .find(|r| r.id == realm)
                .and_then(|r| r.display_name.clone());
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": realm,
                    "issuer": issuer,
                    "display_name": display_name,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "realm not found" })),
        )
            .into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn delete_realm<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::RealmAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.delete_realm(&RealmId(realm.clone())).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(realm.clone()),
                "realm.delete",
                "realm",
                &realm,
                serde_json::json!({}),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

// ── User handlers ─────────────────────────────────────────────────────────────

pub(crate) async fn list_users<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::DirectoryAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.list_users(&RealmId(realm)).await {
        Ok(users) => {
            let items: Vec<serde_json::Value> = users
                .into_iter()
                .map(|u| {
                    serde_json::json!({
                        "id": u.id,
                        "realm_id": u.realm_id,
                        "email": u.email,
                        "email_verified": u.email_verified,
                        "display_name": u.display_name,
                    })
                })
                .collect();
            (StatusCode::OK, Json(serde_json::json!(items))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateUserRequest {
    id: Option<String>,
    email: String,
    display_name: Option<String>,
}

pub(crate) async fn create_user<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::DirectoryAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let user_id = req.id.unwrap_or_else(|| Ulid::new().to_string());
    let user = User {
        id: user_id.clone(),
        realm_id: realm.clone(),
        email: Some(req.email),
        email_verified: false,
        display_name: req.display_name,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    match state.repo.create_user(&user).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(realm.clone()),
                "user.create",
                "user",
                &user_id,
                serde_json::json!({ "email": user.email, "display_name": user.display_name }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "id": user_id,
                    "realm_id": realm,
                    "email": user.email,
                    "email_verified": false,
                    "display_name": user.display_name,
                })),
            )
                .into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn get_user<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path((realm, user_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::DirectoryAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.get_user_by_id(&user_id).await {
        Ok(Some(u)) => {
            if u.realm_id != realm {
                return qid_http::error_response(QidError::NotFound {
                    resource: format!("user {user_id}"),
                });
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": u.id,
                    "realm_id": u.realm_id,
                    "email": u.email,
                    "email_verified": u.email_verified,
                    "display_name": u.display_name,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "user not found" })),
        )
            .into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

#[derive(Deserialize)]
pub(crate) struct UpdateUserRequest {
    email: Option<String>,
    display_name: Option<String>,
    email_verified: Option<bool>,
}

pub(crate) async fn update_user<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((realm, user_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<UpdateUserRequest>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::DirectoryAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let existing = match state.repo.get_user_by_id(&user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "user not found" })),
            )
                .into_response();
        }
        Err(e) => return qid_http::error_response(e),
    };
    if existing.realm_id != realm {
        return qid_http::error_response(QidError::NotFound {
            resource: format!("user {user_id}"),
        });
    }

    let email_changed = req.email.is_some();
    let display_name_changed = req.display_name.is_some();
    let email_verified_changed = req.email_verified.is_some();
    let updated = User {
        id: user_id.clone(),
        realm_id: existing.realm_id.clone(),
        email: req.email.or(existing.email),
        email_verified: req.email_verified.unwrap_or(existing.email_verified),
        display_name: req.display_name.or(existing.display_name),
        failed_login_attempts: existing.failed_login_attempts,
        locked_until: existing.locked_until,
        org: existing.org,
    };
    let target_realm = realm.clone();

    match state.repo.update_user(&updated).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(target_realm),
                "user.update",
                "user",
                &user_id,
                serde_json::json!({
                    "email_changed": email_changed,
                    "display_name_changed": display_name_changed,
                    "email_verified_changed": email_verified_changed,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": updated.id,
                    "realm_id": updated.realm_id,
                    "email": updated.email,
                    "email_verified": updated.email_verified,
                    "display_name": updated.display_name,
                })),
            )
                .into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn delete_user<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((realm, user_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::DirectoryAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let existing = match state.repo.get_user_by_id(&user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "user not found" })),
            )
                .into_response();
        }
        Err(e) => return qid_http::error_response(e),
    };
    if existing.realm_id != realm {
        return qid_http::error_response(QidError::NotFound {
            resource: format!("user {user_id}"),
        });
    }
    match state.repo.delete_user(&user_id).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(realm),
                "user.delete",
                "user",
                &user_id,
                serde_json::json!({}),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

// ── Client handlers ───────────────────────────────────────────────────────────

pub(crate) async fn list_clients<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.list_clients(&RealmId(realm)).await {
        Ok(clients) => {
            let items: Vec<serde_json::Value> = clients
                .into_iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id,
                        "realm_id": c.realm_id,
                        "client_id": c.client_id,
                        "client_type": c.client_type,
                        "redirect_uris": c.redirect_uris,
                        "grant_types": c.grant_types,
                    })
                })
                .collect();
            (StatusCode::OK, Json(serde_json::json!(items))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateClientRequest {
    client_id: String,
    client_type: ClientType,
    client_secret: Option<String>,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
}

pub(crate) async fn create_client<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateClientRequest>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::AppAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let token_endpoint_auth_method = match req.client_type {
        ClientType::Public => "none".to_string(),
        ClientType::Confidential => qid_core::models::default_token_endpoint_auth_method(),
    };
    let client_secret_hash = match req.client_type {
        ClientType::Public => {
            if req.client_secret.is_some() {
                return qid_http::error_response(QidError::BadRequest {
                    message: "public clients must not declare client_secret".to_string(),
                });
            }
            None
        }
        ClientType::Confidential => {
            let Some(secret) = req.client_secret.as_deref() else {
                return qid_http::error_response(QidError::BadRequest {
                    message: "confidential clients require client_secret".to_string(),
                });
            };
            Some(qid_core::util::client_secret_hash(secret))
        }
    };
    let client = Client {
        id: Ulid::new().to_string(),
        realm_id: realm.clone(),
        client_id: req.client_id,
        client_type: req.client_type,
        token_endpoint_auth_method,
        client_secret_hash,
        mtls_certificate_thumbprints: Vec::new(),
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: req.redirect_uris,
        grant_types: req.grant_types,
        client_name: None,
        client_uri: None,
        logo_uri: None,
        contacts: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        default_max_age: None,
        require_auth_time: false,
        sector_identifier_uri: None,
        subject_type: None,
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        backchannel_client_notification_endpoint: None,
    };
    match state.repo.create_client(&client).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(realm),
                "client.create",
                "client",
                &client.client_id,
                serde_json::json!({
                    "client_type": client.client_type,
                    "redirect_uris": client.redirect_uris,
                    "grant_types": client.grant_types,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "id": client.id,
                    "realm_id": client.realm_id,
                    "client_id": client.client_id,
                    "client_type": client.client_type,
                    "redirect_uris": client.redirect_uris,
                    "grant_types": client.grant_types,
                })),
            )
                .into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn delete_client<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((realm, client_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::AppAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let client = match state
        .repo
        .get_client_by_client_id(&RealmId(realm.clone()), &client_id)
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "client not found" })),
            )
                .into_response();
        }
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.delete_client(&client.id).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(realm),
                "client.delete",
                "client",
                &client_id,
                serde_json::json!({ "client_internal_id": client.id }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}
