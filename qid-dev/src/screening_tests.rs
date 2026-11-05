use super::*;

#[tokio::test]
async fn seed_screening_precedes_new_user_and_replacement_writes_but_not_existing_users() {
    let dir = std::env::temp_dir().join(format!("qid-dev-screening-{}", ulid::Ulid::new()));
    run(Args {
        command: Command::DevInit {
            output: dir.clone(),
            realm: "dev".into(),
            listen: "127.0.0.1:0".into(),
            issuer: None,
            public_base_url: "https://id.example.com".into(),
            force: false,
        },
    })
    .await
    .unwrap();
    let config_path = dir.join("qid.yaml");
    let users = dir.join("screened.json");
    std::fs::write(
        &users,
        r#"[{"email":"screened@example.com","password":"test-password","email_verified":true}]"#,
    )
    .unwrap();
    let mut yaml = std::fs::read_to_string(&config_path).unwrap();
    yaml = yaml.replace(
        "      password:\n",
        "      password:\n        argon2id: {memory_kib: 8, time_cost: 1, parallelism: 1}\n",
    );
    let screened_yaml = yaml.replace("      password:\n", "      password:\n        screening:\n          sha256_hex: [\"c638833f69bbfb3c267afa0a74434812436b8f08a81fd263c6be6871de4f1265\"]\n");
    std::fs::write(&config_path, &screened_yaml).unwrap();
    assert!(
        seed_users(&config_path, &users, None, false)
            .await
            .unwrap_err()
            .to_string()
            .contains("password_not_allowed")
    );
    let config = QidConfig::from_file(config_path.to_str().unwrap()).unwrap();
    let repo = open_repo(&config).await.unwrap();
    assert!(
        repo.get_user_by_email(&"dev".into(), "screened@example.com")
            .await
            .unwrap()
            .is_none()
    );
    drop(repo);
    std::fs::write(&config_path, yaml).unwrap();
    seed_users(&config_path, &users, None, false).await.unwrap();
    std::fs::write(&config_path, screened_yaml).unwrap();
    let repo = open_repo(&config).await.unwrap();
    let user = repo
        .get_user_by_email(&"dev".into(), "screened@example.com")
        .await
        .unwrap()
        .unwrap();
    let old = repo
        .get_password_credential(&user.id)
        .await
        .unwrap()
        .unwrap();
    drop(repo);
    // Existing users without --replace-password are not screened.
    seed_users(&config_path, &users, None, false).await.unwrap();
    assert!(
        seed_users(&config_path, &users, None, true)
            .await
            .unwrap_err()
            .to_string()
            .contains("password_not_allowed")
    );
    let repo = open_repo(&config).await.unwrap();
    let after = repo
        .get_password_credential(&user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.hash, old.hash);
    assert_eq!(
        serde_json::to_value(repo.get_user_by_id(&user.id).await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(user).unwrap()
    );
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}
