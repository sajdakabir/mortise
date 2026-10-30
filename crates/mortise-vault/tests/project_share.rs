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
