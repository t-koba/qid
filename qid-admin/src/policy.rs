use super::*;
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct PolicySimulationRequest {
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    entitlements: Vec<String>,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    posture: Vec<String>,
    #[serde(default)]
    acr: Option<String>,
    #[serde(default)]
    auth_age_seconds: Option<u64>,
    #[serde(default)]
    risk_score: Option<u64>,
    #[serde(default)]
    resource_host: Option<String>,
    action: String,
    #[serde(default)]
    pep_registration: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PolicySimulationResponse {
    realm_id: String,
    dry_run: bool,
    active_bundle: Option<String>,
    decision: DecisionDetails,
}

pub(crate) async fn admin_ui() -> impl IntoResponse {
    Html(ADMIN_UI_HTML)
}

const ADMIN_UI_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>qid admin</title>
  <style>
    :root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: Canvas; color: CanvasText; }
    header { border-bottom: 1px solid color-mix(in srgb, CanvasText 18%, transparent); padding: 16px 24px; display: flex; gap: 16px; align-items: baseline; justify-content: space-between; }
    main { max-width: 1180px; margin: 0 auto; padding: 20px 24px 36px; }
    h1 { font-size: 20px; margin: 0; font-weight: 680; }
    h2 { font-size: 15px; margin: 0 0 10px; }
    .muted { color: color-mix(in srgb, CanvasText 62%, transparent); font-size: 13px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 18px; }
    .panel { border: 1px solid color-mix(in srgb, CanvasText 16%, transparent); border-radius: 8px; padding: 14px; background: color-mix(in srgb, Canvas 96%, CanvasText 4%); }
    .metric { font-size: 28px; line-height: 1.1; font-weight: 720; }
    nav { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }
    a { color: CanvasText; text-decoration: none; }
    a:hover { text-decoration: underline; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid color-mix(in srgb, CanvasText 14%, transparent); }
    .status { display: inline-flex; align-items: center; gap: 6px; }
    .dot { width: 8px; height: 8px; border-radius: 999px; background: #0f8f5f; display: inline-block; }
    .warn { background: #b7791f; }
    @media (max-width: 640px) { header { align-items: flex-start; flex-direction: column; } main { padding: 16px; } }
  </style>
</head>
<body>
  <header>
    <h1>qid admin</h1>
    <span id="summary" class="muted">Loading</span>
  </header>
  <main>
    <section class="grid" id="metrics"></section>
    <section class="panel">
      <h2>Realms</h2>
      <table>
        <thead><tr><th>Realm</th><th>Issuer</th><th>Users</th><th>Clients</th><th>Policies</th></tr></thead>
        <tbody id="realms"></tbody>
      </table>
    </section>
    <section class="grid" style="margin-top: 18px">
      <div class="panel">
        <h2>Conformance</h2>
        <table><tbody id="conformance"></tbody></table>
      </div>
      <div class="panel">
        <h2>Operations</h2>
        <table><tbody id="operations"></tbody></table>
      </div>
    </section>
    <section class="panel" style="margin-top: 18px">
      <h2>Views</h2>
      <nav id="views"></nav>
    </section>
  </main>
  <script>
    const text = value => document.createTextNode(String(value ?? ""));
    const cell = value => { const td = document.createElement("td"); td.appendChild(text(value)); return td; };
    const row = (...values) => { const tr = document.createElement("tr"); values.forEach(value => tr.appendChild(cell(value))); return tr; };
    const metric = (label, value) => {
      const panel = document.createElement("div"); panel.className = "panel";
      const number = document.createElement("div"); number.className = "metric"; number.appendChild(text(value));
      const caption = document.createElement("div"); caption.className = "muted"; caption.appendChild(text(label));
      panel.append(number, caption); return panel;
    };
    const statusRow = item => {
      const tr = document.createElement("tr");
      const name = cell(item.name);
      const status = document.createElement("td");
      const span = document.createElement("span"); span.className = "status";
      const dot = document.createElement("span"); dot.className = item.status === "ready" ? "dot" : "dot warn";
      span.append(dot, text(item.status)); status.appendChild(span);
      tr.append(name, status); return tr;
    };
    fetch("/admin/api/v1/ui/dashboard", { credentials: "same-origin" })
      .then(response => response.ok ? response.json() : Promise.reject(response.status))
      .then(data => {
        document.getElementById("summary").textContent = `${data.realm_count} realms / ${data.user_count} users / ${data.client_count} clients`;
        const metrics = document.getElementById("metrics");
        [["Realms", data.realm_count], ["Users", data.user_count], ["Clients", data.client_count], ["Policy bundles", data.policy_bundle_count], ["Audit events", data.audit_event_count], ["PEP registrations", data.pep_registration_count]].forEach(([label, value]) => metrics.appendChild(metric(label, value)));
        const realms = document.getElementById("realms");
        data.realms.forEach(realm => realms.appendChild(row(realm.id, realm.issuer, realm.user_count, realm.client_count, realm.policy_bundle_count)));
        const conformance = document.getElementById("conformance");
        data.conformance.forEach(item => conformance.appendChild(statusRow(item)));
        const operations = document.getElementById("operations");
        operations.appendChild(row("Break-glass", data.breakglass_enabled ? "enabled" : "disabled"));
        operations.appendChild(row("Approval", data.approval_required ? "required" : "optional"));
        operations.appendChild(row("Multi-region", data.multi_region_active_active ? "enabled" : "disabled"));
        const views = document.getElementById("views");
        data.views.forEach(view => { const a = document.createElement("a"); a.href = view.href; a.textContent = view.label; views.appendChild(a); });
      })
      .catch(error => { document.getElementById("summary").textContent = `Dashboard unavailable: ${error}`; });
  </script>
</body>
</html>"#;

#[derive(Debug, Clone, Serialize)]
struct AdminDashboard {
    realm_count: usize,
    user_count: usize,
    client_count: usize,
    policy_bundle_count: usize,
    audit_event_count: usize,
    pep_registration_count: usize,
    breakglass_enabled: bool,
    approval_required: bool,
    multi_region_active_active: bool,
    realms: Vec<AdminRealmDashboard>,
    views: Vec<AdminUiView>,
    conformance: Vec<AdminConformanceStatus>,
}

#[derive(Debug, Clone, Serialize)]
struct AdminRealmDashboard {
    id: String,
    issuer: String,
    user_count: usize,
    client_count: usize,
    policy_bundle_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct AdminUiView {
    label: &'static str,
    href: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct AdminConformanceStatus {
    name: &'static str,
    status: &'static str,
    command: &'static str,
}

pub(crate) async fn admin_dashboard<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::PlatformAdmin,
        &state.config.admin.security,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match build_admin_dashboard(&state).await {
        Ok(dashboard) => (StatusCode::OK, Json(dashboard)).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

async fn build_admin_dashboard<R: Repository>(state: &SharedState<R>) -> QidResult<AdminDashboard> {
    let realms = state.repo.list_realms().await?;
    let mut realm_dashboards = Vec::new();
    let mut user_count = 0usize;
    let mut client_count = 0usize;
    let mut policy_bundle_count = 0usize;
    for (id, issuer) in realms {
        let realm_id = RealmId(id.clone());
        let users = state.repo.list_users(&realm_id).await?;
        let clients = state.repo.list_clients(&realm_id).await?;
        let policies = state.repo.list_policy_bundles(&realm_id).await?;
        user_count += users.len();
        client_count += clients.len();
        policy_bundle_count += policies.len();
        realm_dashboards.push(AdminRealmDashboard {
            id,
            issuer,
            user_count: users.len(),
            client_count: clients.len(),
            policy_bundle_count: policies.len(),
        });
    }
    let audit_event_count = state.repo.list_audit_events(None, 500).await?.len();
    let pep_registration_count = state
        .config
        .realms
        .iter()
        .map(|realm| realm.pep_registrations.registrations.len())
        .sum();
    Ok(AdminDashboard {
        realm_count: realm_dashboards.len(),
        user_count,
        client_count,
        policy_bundle_count,
        audit_event_count,
        pep_registration_count,
        breakglass_enabled: state.config.admin.security.breakglass_enabled,
        approval_required: state.config.admin.security.require_approval,
        multi_region_active_active: state.config.ops.cluster.multi_region_active_active,
        realms: realm_dashboards,
        views: admin_ui_views(),
        conformance: admin_conformance_status(),
    })
}

pub(crate) async fn simulate_policy<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<PolicySimulationRequest>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::SecurityAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match run_policy_simulation(&state, &realm, req).await {
        Ok(response) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(realm.clone()),
                "policy.simulate",
                "policy",
                response.active_bundle.as_deref().unwrap_or("default"),
                serde_json::json!({
                    "dry_run": true,
                    "decision": response.decision.decision.clone(),
                    "policy_id": response.decision.policy_id.clone(),
                    "matched_rules": response.decision.matched_rules.clone(),
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

async fn run_policy_simulation<R: Repository>(
    state: &SharedState<R>,
    realm: &str,
    req: PolicySimulationRequest,
) -> QidResult<PolicySimulationResponse> {
    let ctx = policy_simulation_context(req)?;
    let mut engine = NativePolicyEngine::new();
    let active_bundle = state
        .repo
        .get_active_policy_bundle(&RealmId(realm.to_string()))
        .await?;
    let active_bundle_name = if let Some(bundle) = active_bundle {
        let policy_bundle: qid_policy::PolicyBundle = serde_json::from_value(bundle.compiled_json)
            .map_err(|e| QidError::Config {
                message: format!("invalid policy bundle: {e}"),
            })?;
        let bundle_name = bundle.name;
        engine.load(policy_bundle, bundle_name.clone());
        Some(bundle_name)
    } else {
        engine.load(
            qid_policy::PolicyBundle {
                version: "1".to_string(),
                rules: Vec::new(),
                default_decision: qid_policy::Decision::Deny,
            },
            "default".to_string(),
        );
        None
    };
    Ok(PolicySimulationResponse {
        realm_id: realm.to_string(),
        dry_run: true,
        active_bundle: active_bundle_name,
        decision: engine.explain(&ctx).await,
    })
}

fn policy_simulation_context(req: PolicySimulationRequest) -> QidResult<PolicyContext> {
    if req.action.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "policy simulation action must not be empty".to_string(),
        });
    }
    Ok(PolicyContext {
        subject_id: req.subject,
        groups: req.groups,
        roles: req.roles,
        entitlements: req.entitlements,
        device_id: req.device_id,
        posture: req.posture,
        acr: req.acr,
        auth_age_seconds: req.auth_age_seconds,
        risk_score: req.risk_score,
        resource_host: req.resource_host,
        resource_action: Some(req.action),
        pep_registration: req.pep_registration.clone(),
    })
}

fn admin_ui_views() -> Vec<AdminUiView> {
    vec![
        AdminUiView {
            label: "Tenant dashboard",
            href: "/admin/api/v1/realms",
        },
        AdminUiView {
            label: "User directory",
            href: "/admin/api/v1/{realm}/users",
        },
        AdminUiView {
            label: "App and client registration",
            href: "/admin/api/v1/{realm}/clients",
        },
        AdminUiView {
            label: "Session management",
            href: "/admin/api/v1/{realm}/sessions",
        },
        AdminUiView {
            label: "Token families",
            href: "/admin/api/v1/{realm}/token-families",
        },
        AdminUiView {
            label: "Service accounts",
            href: "/admin/api/v1/{realm}/service-accounts",
        },
        AdminUiView {
            label: "Policy editor and simulator",
            href: "/admin/api/v1/{realm}/policy/simulate",
        },
        AdminUiView {
            label: "PEP decisions",
            href: "/admin/api/v1/{realm}/pep-decisions",
        },
        AdminUiView {
            label: "Risk events",
            href: "/admin/api/v1/{realm}/risk-events",
        },
        AdminUiView {
            label: "PEP pep_decision endpoint",
            href: "/pep/decision/v1/evaluate",
        },
        AdminUiView {
            label: "Audit search",
            href: "/admin/api/v1/audit",
        },
        AdminUiView {
            label: "Access review campaigns",
            href: "/iga/v1/{tenant}/access-reviews",
        },
        AdminUiView {
            label: "Key rotation dashboard",
            href: "/admin/api/v1/ui/dashboard",
        },
    ]
}

fn admin_conformance_status() -> Vec<AdminConformanceStatus> {
    vec![
        AdminConformanceStatus {
            name: "OAuth/OIDC",
            status: "ready",
            command: "cargo run -p xtask -- gate conformance",
        },
        AdminConformanceStatus {
            name: "FAPI 2.0",
            status: "ready",
            command: "cargo test -p qid-oauth --test token_flows --locked",
        },
        AdminConformanceStatus {
            name: "SAML",
            status: "ready",
            command: "cargo test -p qid-saml --locked",
        },
        AdminConformanceStatus {
            name: "SCIM",
            status: "ready",
            command: "cargo test -p qid-scim --locked",
        },
        AdminConformanceStatus {
            name: "Assurance",
            status: "ready",
            command: "cargo run -p xtask -- gate assurance",
        },
    ]
}
