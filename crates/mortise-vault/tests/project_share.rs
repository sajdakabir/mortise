use mortise_crypto::kdf::Argon2Params;
use mortise_vault::Vault;
use tempfile::TempDir;

const FAST: Argon2Params = Argon2Params {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};

#[test]
fn project_manifest_mutations_materialize_and_remain_available_while_locked() {
    let dir = TempDir::new().unwrap();
    let (mut vault, _) = Vault::create(dir.path().join("project.db"), b"password", FAST).unwrap();
    let cert = vault
        .identity()
        .unwrap()
        .certify(vault.device().unwrap().public(), 1);

    vault
        .set_shared_project_info("Payments", "Production credentials")
        .unwrap();
    vault.add_shared_project_environment("Prod").unwrap();
    vault.add_shared_project_environment("prod").unwrap();
    vault.set_own_project_member_label(&cert, "Sajda").unwrap();

    vault.lock();
    let manifest = vault.shared_project_manifest().unwrap().unwrap();
    assert_eq!(manifest.name, "Payments");
    assert_eq!(manifest.description, "Production credentials");
    assert_eq!(manifest.environments, ["Prod"]);
    assert_eq!(manifest.members.len(), 1);
    assert_eq!(manifest.members[0].name, "Sajda");
    assert_eq!(manifest.members[0].cert, cert.to_bytes());
}

#[test]
fn project_manifest_plaintext_is_not_written_to_the_database() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("project.db");
    let (mut vault, _) = Vault::create(&path, b"password", FAST).unwrap();
    vault
        .set_shared_project_info("acme-payroll", "super secret system")
        .unwrap();
    vault.checkpoint().unwrap();
    drop(vault);

    let bytes = std::fs::read(path).unwrap();
    assert!(
        !bytes
            .windows(b"acme-payroll".len())
            .any(|w| w == b"acme-payroll")
    );
    assert!(
        !bytes
            .windows(b"super secret system".len())
            .any(|w| w == b"super secret system")
    );
}

#[test]
fn a_project_vault_is_an_independent_file_with_the_accounts_device_identity() {
    let dir = TempDir::new().unwrap();
    let (account, _) = Vault::create(dir.path().join("personal.db"), b"password", FAST).unwrap();
    let account_vault = account.meta().vault_id;
    let account_device = account.device_id().unwrap();

    let project = Vault::create_project_vault(
        dir.path().join("payments.db"),
        &account,
        "Payments",
        "Shared deploy keys",
    )
    .unwrap();

    assert_ne!(project.meta().vault_id, account_vault);
    assert_eq!(project.device_id().unwrap(), account_device);
    assert_eq!(
        project.acl().unwrap().role(account_device),
        Some(mortise_crypto::acl::Role::Owner)
    );
    assert_eq!(project.known_epochs().unwrap(), [0]);
    assert_eq!(
        project.shared_project_manifest().unwrap().unwrap().name,
        "Payments"
    );
    assert!(account.shared_project_manifest().unwrap().is_none());
}

#[test]
fn an_invite_creates_a_keyless_vault_pinned_to_its_genesis_owner() {
    let dir = TempDir::new().unwrap();
    let (owner, _) = Vault::create(dir.path().join("owner.db"), b"password", FAST).unwrap();
    let (account, _) = Vault::create(dir.path().join("joiner.db"), b"password", FAST).unwrap();

    let waiting = Vault::create_waiting_project_vault(
        dir.path().join("waiting.db"),
        &account,
        owner.meta().vault_id,
        owner.device().unwrap().public(),
    )
    .unwrap();

    assert!(waiting.is_unlocked());
    assert!(waiting.known_epochs().unwrap().is_empty());
    assert_eq!(
        waiting.acl().unwrap().role(owner.device_id().unwrap()),
        Some(mortise_crypto::acl::Role::Owner)
    );
    assert_eq!(
        waiting.acl().unwrap().role(waiting.device_id().unwrap()),
        None
    );
}

#[test]
fn environment_secrets_use_stable_ids_and_replace_the_same_key() {
    let dir = TempDir::new().unwrap();
    let (account, _) = Vault::create(dir.path().join("personal.db"), b"password", FAST).unwrap();
    let mut project =
        Vault::create_project_vault(dir.path().join("project.db"), &account, "API", "").unwrap();

    let first = project
        .upsert_project_env_secret("Prod", "TOKEN", "one")
        .unwrap();
    let second = project
        .upsert_project_env_secret("prod", "TOKEN", "two")
        .unwrap();

    assert_eq!(first, second);
    assert_eq!(project.item_count().unwrap(), 1);
    assert_eq!(
        project.reveal(first).unwrap(),
        mortise_vault::model::ItemPayload::EnvSecret {
            value: "two".into()
        }
    );
}
