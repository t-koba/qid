use super::*;
use async_trait::async_trait;
use qid_core::models::{ScimGroup, User};
use qid_storage::SqlRepository;
use serde_json::json;
use std::sync::Mutex;

#[derive(Default)]
struct Remote {
    users: Vec<Value>,
    groups: Vec<Value>,
    requests: Vec<OutboundScimHttpRequest>,
    malformed: bool,
    fail_write: bool,
}
struct Transport(Mutex<Remote>);
impl Transport {
    fn new(remote: Remote) -> Self {
        Self(Mutex::new(remote))
    }
}
impl std::ops::Deref for Transport {
    type Target = Mutex<Remote>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[async_trait]
impl OutboundScimTransport for Transport {
    async fn send(&self, request: OutboundScimHttpRequest) -> QidResult<OutboundScimHttpResponse> {
        let mut remote = self.lock().unwrap();
        let url = reqwest::Url::parse(&request.url).unwrap();
        let collection = url.path().contains("/Users");
        remote.requests.push(request.clone());
        if request.method == "GET" {
            if remote.malformed {
                return Ok(OutboundScimHttpResponse {
                    status: 200,
                    body: Some(json!({"Resources": []})),
                });
            }
            let mut resources = if collection {
                remote.users.clone()
            } else {
                remote.groups.clone()
            };
            let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
            if let Some(filter) = query.get("filter") {
                let external: String =
                    serde_json::from_str(filter.strip_prefix("externalId eq ").unwrap()).unwrap();
                resources.retain(|r| r["externalId"] == external);
            }
            let total = resources.len();
            let start: usize = query["startIndex"].parse().unwrap();
            let count: usize = query["count"].parse().unwrap();
            let page: Vec<_> = resources.into_iter().skip(start - 1).take(count).collect();
            return Ok(OutboundScimHttpResponse {
                status: 200,
                body: Some(
                    json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults":total,"startIndex":start,"itemsPerPage":page.len(),"Resources":page}),
                ),
            });
        }
        if remote.fail_write {
            return Err(invalid("private remote body and bearer fixture-value"));
        }
        let resources = if collection {
            &mut remote.users
        } else {
            &mut remote.groups
        };
        let mut body = request.body.unwrap_or(Value::Null);
        let id = url.path_segments().unwrap().next_back().unwrap();
        match request.method.as_str() {
            "POST" => {
                assert!(
                    !resources
                        .iter()
                        .any(|r| r["externalId"] == body["externalId"])
                );
                body["id"] = json!(format!("remote-{}", resources.len()));
                resources.push(body.clone());
            }
            "PUT" => {
                let current = resources
                    .iter_mut()
                    .find(|r| r["id"] == id)
                    .expect("PUT must address remote id");
                body["id"] = current["id"].clone();
                *current = body.clone();
            }
            "PATCH" => {
                resources.iter_mut().find(|r| r["id"] == id).unwrap()["active"] = json!(false)
            }
            "DELETE" => resources.retain(|r| r["id"] != id),
            other => panic!("unexpected method {other}"),
        }
        Ok(OutboundScimHttpResponse {
            status: if request.method == "POST" { 201 } else { 200 },
            body: Some(body),
        })
    }
}
fn user(id: &str) -> ScimUser {
    ScimUser {
        id: id.into(),
        realm_id: "corp".into(),
        external_id: None,
        user_name: format!("{id}@example.com"),
        name_json: json!({}),
        emails_json: json!([]),
        enterprise_json: json!({}),
        directory_provider_id: None,
        deprovisioned_at: None,
        active: true,
    }
}
pub(super) fn config(dry_run: bool) -> ScimOutboundSyncConfig {
    ScimOutboundSyncConfig {
        realm_id: "corp".into(),
        actor: "worker".into(),
        reason: "test".into(),
        now_epoch: 100,
        record_audit_event: true,
        scim_base_url: "https://scim.example/scim/v2".into(),
        scim_bearer_token: None,
        dry_run,
    }
}
pub(super) async fn seed(repo: &SqlRepository) {
    for realm in ["corp", "other"] {
        repo.create_realm(
            &"default".into(),
            &realm.into(),
            &format!("https://id.example/{realm}"),
            None,
        )
        .await
        .unwrap();
    }
}
async fn run(repo: &SqlRepository, remote: &Transport, dry: bool) -> ScimOutboundSyncReport {
    run_scim_outbound_sync_with_transport(
        repo,
        config(dry),
        ScimOutboundSyncOptions::default(),
        remote,
    )
    .await
    .unwrap()
}
#[tokio::test]
async fn outbound_uses_only_realm_scim_registry_and_repeated_apply_is_noop() {
    crate::test_support::with_repo(async |repo, _| {
        seed(&repo).await;
        repo.create_scim_user(&user("alice")).await.unwrap();
        repo.create_scim_user(&ScimUser {
            id: "foreign".into(),
            realm_id: "other".into(),
            ..user("alice")
        })
        .await
        .unwrap();
        // Same email is deliberately not a trusted identity link; lockout cannot deactivate SCIM.
        for (id, email) in [
            ("login", "alice@example.com"),
            ("login-only", "other@example.com"),
        ] {
            repo.create_user(&User {
                id: id.into(),
                realm_id: "corp".into(),
                email: Some(email.into()),
                email_verified: true,
                display_name: None,
                failed_login_attempts: 4,
                locked_until: Some(500),
                org: None,
            })
            .await
            .unwrap();
        }
        let remote = Transport::new(Remote::default());
        let dry = run(&repo, &remote, true).await;
        assert_eq!((dry.failed, dry.synced, dry.planned), (0, 0, 1));
        assert!(
            remote
                .lock()
                .unwrap()
                .requests
                .iter()
                .all(|r| r.method == "GET")
        );
        let apply = run(&repo, &remote, false).await;
        assert_eq!((apply.failed, apply.synced, apply.planned), (0, 1, 1));
        assert_eq!(remote.lock().unwrap().users[0]["active"], true);
        let again = run(&repo, &remote, false).await;
        assert_eq!(
            (again.failed, again.synced, again.skipped, again.planned),
            (0, 0, 1, 0)
        );
        {
            let state = remote.lock().unwrap();
            assert_eq!(state.users.len(), 1);
            assert_eq!(state.users[0]["externalId"], "alice");
            assert_eq!(
                state.requests.iter().filter(|r| r.method == "POST").count(),
                1
            );
        }
        let events = repo
            .list_audit_events(Some(&"corp".into()), 10)
            .await
            .unwrap();
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|e| e.action == "scim.outbound_sync"));
    })
    .await;
}
#[tokio::test]
async fn outbound_deprovisions_and_reconciles_remote_group_member_ids() {
    crate::test_support::with_repo(async |repo, _| {
        seed(&repo).await;
        let mut inactive = user("inactive");
        inactive.external_id = Some("stable-external".into());
        inactive.deprovisioned_at = Some(99);
        let active = user("active");
        repo.create_scim_user(&inactive).await.unwrap();
        repo.create_scim_user(&active).await.unwrap();
        repo.create_scim_group(&ScimGroup { external_id: None, id:"local-g".into(), realm_id:"corp".into(), display_name:"renamed".into(), members_json:json!([{"value":"inactive"},{"value":"active"}]) }).await.unwrap();
        let mut old = render_outbound_user(&inactive, &default_outbound_user_mapping()).unwrap();
        old["active"] = json!(true);
        old["id"] = json!("remote-inactive");
        let mut current = render_outbound_user(&active, &default_outbound_user_mapping()).unwrap();
        current["id"] = json!("remote-active");
        let remote = Transport::new(Remote { users:vec![old,current], groups:vec![json!({"id":"remote-g","externalId":"local-g","displayName":"old-name","members":[{"value":"remote-inactive"}]})], ..Remote::default() });
        assert_eq!(run(&repo, &remote, false).await.synced, 2);
        assert_eq!(run(&repo, &remote, false).await.synced, 0);
        let state = remote.lock().unwrap();
        assert_eq!(state.users[0]["active"], false);
        assert_eq!(state.groups[0]["members"], json!([{"value":"remote-active"}]));
        let writes: Vec<_> = state.requests.iter().filter(|r| r.method != "GET").collect();
        assert_eq!(writes.len(), 2);
        assert!(writes.iter().all(|r| r.method == "PUT" && !r.url.contains('?')));
        assert!(writes.iter().any(|r| r.url.ends_with("/Groups/remote-g")));
    }).await;
}
#[tokio::test]
async fn outbound_fails_closed_and_reports_safe_errors_including_audit_failure() {
    crate::test_support::with_repo(async |repo, dir| {
        seed(&repo).await;
        repo.create_scim_user(&user("alice")).await.unwrap();
        for remote in [Remote { malformed:true, ..Remote::default() }, Remote { users:vec![json!({"id":"a","externalId":"alice"}),json!({"id":"b","externalId":"alice"})], ..Remote::default() }] {
            let remote = Transport::new(remote);
            let report = run(&repo, &remote, false).await;
            assert_eq!(report.failed, 1);
            assert!(remote.lock().unwrap().requests.iter().all(|r| r.method == "GET"));
        }
        let remote = Transport::new(Remote { fail_write:true, ..Remote::default() });
        let report = run(&repo, &remote, false).await;
        assert_eq!(report.failed, 1);
        assert!(crate::sync_failed(&json!({"report":report})));
        let serialized = serde_json::to_string(&repo.list_audit_events(None, 10).await.unwrap()).unwrap();
        assert!(!serialized.contains("fixture-value") && !serialized.contains("private remote body"));
        let pool = sqlx::sqlite::SqlitePool::connect(&format!("sqlite:{}", dir.join("test.db").display())).await.unwrap();
        sqlx::query("CREATE TRIGGER fail_outbound_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected'); END;").execute(&pool).await.unwrap();
        pool.close().await;
        let remote = Transport::new(Remote::default());
        let report = run(&repo, &remote, false).await;
        assert_eq!((report.synced, report.failed), (1,1));
        assert!(report.errors[0].contains("audit persistence failed"));
        assert!(report.errors[0].contains("may already have occurred"));
    }).await;
}
#[tokio::test]
async fn outbound_orphans_require_explicit_policy_and_complete_bounded_inventory() {
    crate::test_support::with_repo(async |repo, _| {
        seed(&repo).await;
        let remote = Transport::new(Remote {
            users: vec![
                json!({"id":"orphan","externalId":"absent","active":true}),
                json!({"id":"unmanaged","active":true}),
            ],
            ..Remote::default()
        });
        assert_eq!(run(&repo, &remote, false).await.synced, 0);
        let options = ScimOutboundSyncOptions {
            inventory: OutboundInventoryLimits {
                page_size: 1,
                max_resources: 2,
            },
            orphan_action: Some(OutboundOrphanAction::Deactivate),
        };
        let dry =
            run_scim_outbound_sync_with_transport(&repo, config(true), options.clone(), &remote)
                .await
                .unwrap();
        assert_eq!((dry.planned, dry.synced), (1, 0));
        let bounded = ScimOutboundSyncOptions {
            inventory: OutboundInventoryLimits {
                page_size: 1,
                max_resources: 1,
            },
            ..options.clone()
        };
        assert_eq!(
            run_scim_outbound_sync_with_transport(&repo, config(false), bounded, &remote)
                .await
                .unwrap()
                .failed,
            1
        );
        assert!(
            remote
                .lock()
                .unwrap()
                .requests
                .iter()
                .all(|r| r.method == "GET")
        );
        assert_eq!(
            run_scim_outbound_sync_with_transport(&repo, config(false), options.clone(), &remote)
                .await
                .unwrap()
                .synced,
            1
        );
        assert_eq!(remote.lock().unwrap().users[0]["active"], false);
        let delete = ScimOutboundSyncOptions {
            orphan_action: Some(OutboundOrphanAction::Delete),
            ..options
        };
        assert_eq!(
            run_scim_outbound_sync_with_transport(&repo, config(false), delete, &remote)
                .await
                .unwrap()
                .synced,
            1
        );
        assert_eq!(
            remote.lock().unwrap().users,
            vec![json!({"id":"unmanaged","active":true})]
        );
    })
    .await;
}
