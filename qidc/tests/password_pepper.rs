//! The actual CLI resolves secrets before creating an account.
use qid_core::{
    config::{PasswordSecretSource, QidConfig},
    state::PasswordCredentials,
};
use qid_crypto::CredentialContext;
use qid_storage::{AnyRepository, prelude::*};
use std::{process::Command, sync::Arc};

#[tokio::test]
async fn create_uses_realm_pepper_and_missing_source_leaves_no_account() {
    let dir = std::env::temp_dir().join(format!("qidc-password-pepper-{}", ulid::Ulid::new()));
    std::fs::create_dir(&dir).unwrap();
    let store = dir.join("store.json");
    let config_path = dir.join("qid.yaml");
    let config = serde_json::json!({
        "server":{"listen":"127.0.0.1:0", "public_base_url":"https://id.example.com"},
        "storage":{"primary":{"type":"file", "url":store}},
        "realms":[{"id":"corp", "issuer":"https://id.example.com/realms/corp", "authentication":{"password":{
            "argon2id":{"memory_kib":8,"time_cost":1,"parallelism":1},
            "pepper":{"active":"key1", "keys":{"key1":{"env":"TEST_CLI_PEPPER"}}}
        }}}]
    });
    // JSON is also a YAML document.
    std::fs::write(&config_path, config.to_string()).unwrap();
    let invoke = |secret: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_qidc"));
        command.args([
            "--config",
            config_path.to_str().unwrap(),
            "user",
            "create",
            "--realm",
            "corp",
            "--email",
            "pepper@example.com",
            "--password",
            "test-password",
        ]);
        command.env_remove("TEST_CLI_PEPPER");
        if let Some(secret) = secret {
            command.env("TEST_CLI_PEPPER", secret);
        }
        command.output().unwrap()
    };
    assert!(!invoke(None).status.success());
    let repo = AnyRepository::connect(store.to_str().unwrap())
        .await
        .unwrap();
    assert!(
        repo.get_user_by_email(&"corp".into(), "pepper@example.com")
            .await
            .unwrap()
            .is_none()
    );
    drop(repo);
    let result = invoke(Some("test-only-cli-pepper"));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("test-only-cli-pepper"));
    let repo = Arc::new(
        AnyRepository::connect(store.to_str().unwrap())
            .await
            .unwrap(),
    );
    let user = repo
        .get_user_by_email(&"corp".into(), "pepper@example.com")
        .await
        .unwrap()
        .unwrap();
    let credential = repo
        .get_password_credential(&user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(credential.hash.contains("keyid=a2V5MQ"));
    assert!(
        !std::fs::read_to_string(&store)
            .unwrap()
            .contains("test-only-cli-pepper")
    );
    let secret_file = dir.join("key1");
    std::fs::write(&secret_file, b"test-only-cli-pepper").unwrap();
    let mut config = QidConfig::from_file(config_path.to_str().unwrap()).unwrap();
    config.realms[0]
        .authentication
        .password
        .pepper
        .as_mut()
        .unwrap()
        .keys
        .insert(
            "key1".into(),
            PasswordSecretSource::File {
                file: secret_file.to_str().unwrap().into(),
            },
        );
    let owner = CredentialContext::resolve(&config.realms[0].authentication.password).unwrap();
    assert_eq!(owner.verify("test-password", &credential), (true, false));
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}
