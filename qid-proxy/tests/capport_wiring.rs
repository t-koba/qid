use qid_core::config::ServerPaths;
use qid_proxy::{capport_routes_enabled, captive_portal_routes};
use qid_storage::AnyRepository;

fn config_with_capport(realms: &[(&str, bool)]) -> qid_core::config::QidConfig {
    let mut config = qid_core::test_helpers::test_config();
    let template = config.realms[0].clone();
    config.realms = realms
        .iter()
        .map(|(id, capport)| {
            let mut realm = template.clone();
            realm.id = (*id).to_string();
            realm.protocols.network_aaa.capport = *capport;
            realm
        })
        .collect();
    config
}

#[test]
fn capport_routes_stay_off_by_default() {
    let config = qid_core::test_helpers::test_config();
    assert!(!config.realms[0].protocols.network_aaa.capport);
    assert!(!capport_routes_enabled(&config));
}

#[test]
fn capport_routes_enable_when_any_realm_opts_in() {
    let off = config_with_capport(&[("a", false), ("b", false)]);
    assert!(!capport_routes_enabled(&off));

    let one_on = config_with_capport(&[("a", false), ("b", true)]);
    assert!(capport_routes_enabled(&one_on));

    let all_on = config_with_capport(&[("a", true)]);
    assert!(capport_routes_enabled(&all_on));
}

#[test]
fn captive_portal_routes_accept_default_and_custom_details_paths() {
    let default_paths = ServerPaths::default();
    assert_eq!(
        default_paths.capport_details,
        "/api/v1/:realm/captive-portal/api/v1/details"
    );
    let _default_router = captive_portal_routes::<AnyRepository>(&default_paths);

    let custom_paths = ServerPaths {
        capport_details: "/capport/:realm/status".to_string(),
        ..ServerPaths::default()
    };
    let _custom_router = captive_portal_routes::<AnyRepository>(&custom_paths);
}
