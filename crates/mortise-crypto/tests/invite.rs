//! Team sharing encodings: spec §2.3 (certificates), §6.4 (invites and join
//! requests), §6.5 (fingerprints), §6.7 (environment item ids).
//!
//! The known-answer vectors were produced by an independent Python encoder
//! (`blake3`, `cryptography`), not by this crate, so a test passing means two
//! implementations of the spec agree — not merely that the code matches itself.

use hpke::Serializable;
use mortise_crypto::encode::{Tag, Writer};
use mortise_crypto::error::Error;
use mortise_crypto::identity::{DEVICE_CERT_LEN, Device, DeviceCert, Identity, IdentityPublic};
use mortise_crypto::invite::{
    Invite, InviteSecret, JoinRequest, LINK_PREFIX, MAX_INVITE_LIFETIME_MS, relay_url_allowed,
};
use mortise_crypto::item::ItemId;
use mortise_crypto::secret::Key32;
use mortise_crypto::vault::{Epoch, VaultId, VaultKey};

const NOW: u64 = 1_759_000_000_000;
const DAY: u64 = 86_400_000;

// --- known answers ---

/// Identity seed 01×32, device signing seed 02×32, device X25519 secret 03×32,
/// issued at 1759000000000.
const CERT_HEX: &str = "018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c1eed29b1654fbca94617004d7969dfc48139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3945dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22000001998c91f6008c79d782647e098363831fc0d330c528b1256182a8b562451ac4e87e146f0deb2ce09beffaaa8918e834afb2ddd4f7787cfd909f744aa4755a3adad02c7f5401";
const IDENT_HEX: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const DEV_SIGN_HEX: &str = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";
const DEV_KEX_HEX: &str = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22";
const DEV_ID_HEX: &str = "1eed29b1654fbca94617004d7969dfc4";

/// Vault 07×16, relay https://relay.example, the certificate above as inviter
/// "Ada", project "acme-payroll", owner keys from seeds 04×32 / 05×32, secret
/// 5a×32, expiring a day after NOW.
const LINK: &str = "mortise://join#BAcHBwcHBwcHBwcHBwcHBwcAAAAVaHR0cHM6Ly9yZWxheS5leGFtcGxlAAAAuQGKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXB7tKbFlT7ypRhcATXlp38SBOXcOqH0XX1ajVGbDTH7My42KkbTuN6Jd9g9bj8mzlF3-3Ttr1H9voo7hXZadW7DqU3dNSIva-d8cbgEks-8iAAABmYyR9gCMedeCZH4Jg2ODH8DTMMUosSVhgqi1YkUaxOh-FG8N6yzgm-_6qokY6DSvst3U93h8_ZCfdEqkdVo62tAsf1QBAAAAA0FkYQAAAAxhY21lLXBheXJvbGzKk6wXBRhwcdZ7g8f_Dv6BCOjsRTBXXXcmh5Mz29q-fFCmFAmx3dAyXpsWtwDnGel3LAcACxvXeG6QfGU9IEldWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWloAAAGZkbhSAI3iV8I";
const OWNER_SIGN_HEX: &str = "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c";
const OWNER_KEX_HEX: &str = "50a61409b1ddd0325e9b16b700e719e9772c07000b1bd7786e907c653d20495d";

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().unwrap()
}

#[test]
fn a_certificate_from_another_encoder_parses_and_reencodes_identically() {
    let bytes = h(CERT_HEX);
    assert_eq!(bytes.len(), DEVICE_CERT_LEN);

    let cert = DeviceCert::from_bytes(&bytes).expect("independent vector did not parse");
    assert_eq!(cert.identity().as_bytes(), &h32(IDENT_HEX));
    assert_eq!(cert.device().signing_public(), &h32(DEV_SIGN_HEX));
    assert_eq!(cert.device().kex_public_bytes(), &h32(DEV_KEX_HEX));
    assert_eq!(cert.device().id().as_bytes().as_slice(), h(DEV_ID_HEX));
    assert_eq!(cert.issued_at_ms(), NOW);
    assert_eq!(cert.to_bytes(), bytes, "re-encoding changed the bytes");
}

#[test]
fn the_fingerprint_matches_the_independent_vector() {
    let identity = IdentityPublic::from_bytes(core::array::from_fn(|i| i as u8));
    assert_eq!(
        identity.fingerprint().to_string(),
        "02424 04938 61298 43939 18707 36540 77236 18244 25504 24868 03592 35250"
    );
}

#[test]
fn an_invite_from_another_encoder_parses_and_reencodes_identically() {
    let invite = Invite::from_link(LINK, NOW).expect("independent vector did not parse");
    assert_eq!(invite.vault(), VaultId::from_bytes([7; 16]));
    assert_eq!(invite.relay_url(), "https://relay.example");
    assert_eq!(invite.inviter().to_bytes(), h(CERT_HEX));
    assert_eq!(invite.inviter_name(), "Ada");
    assert_eq!(invite.project_name(), "acme-payroll");
    assert_eq!(invite.owner().signing_public(), &h32(OWNER_SIGN_HEX));
    assert_eq!(invite.owner().kex_public_bytes(), &h32(OWNER_KEX_HEX));
    assert_eq!(invite.secret().expose(), &[0x5a; 32]);
    assert_eq!(invite.expires_at_ms(), NOW + DAY);
    assert_eq!(invite.to_link(), LINK, "re-encoding changed the link");
}

#[test]
fn the_mailbox_id_matches_the_independent_vector() {
    let secret = InviteSecret::from_bytes([0x5a; 32]);
    assert_eq!(
        secret.mailbox_id().unwrap().as_bytes().as_slice(),
        h("02313260ce08f2515f4b2300a79893d5")
    );
}

#[test]
fn environment_item_ids_match_the_independent_vector() {
    let key = VaultKey::from_parts(Key32::new([0x42; 32]), Epoch::INITIAL);
    let vault = VaultId::from_bytes([7; 16]);
    let id = |env, name| ItemId::for_env_secret(&key, vault, env, name).unwrap();

    assert_eq!(
        id("Prod", "STRIPE_SECRET_KEY").as_bytes().as_slice(),
        h("0f0c84f7cc0bc17bf9bd9edbbdbf2f1a")
    );
    assert_eq!(
        id("dev", "STRIPE_SECRET_KEY").as_bytes().as_slice(),
        h("49b4489180e20cf1b4066f0e37926602")
    );
}

// --- device certificates ---

#[test]
fn a_certificate_round_trips() {
    let identity = Identity::generate().unwrap();
    let device = Device::generate().unwrap();
    let cert = identity.certify(device.public(), NOW);
    assert_eq!(DeviceCert::from_bytes(&cert.to_bytes()).unwrap(), cert);
}

/// Every byte of a certificate is load-bearing: the tag, the identity, the id,
/// both keys, the time and the signature. Flipping any one must be refused.
#[test]
fn flipping_any_byte_of_a_certificate_is_refused() {
    let bytes = h(CERT_HEX);
    for i in 0..bytes.len() {
        let mut tampered = bytes.clone();
        tampered[i] ^= 0x01;
        assert!(
            DeviceCert::from_bytes(&tampered).is_err(),
            "byte {i} could be altered without detection"
        );
    }
}

#[test]
fn a_truncated_or_extended_certificate_is_refused() {
    let bytes = h(CERT_HEX);
    assert!(DeviceCert::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(DeviceCert::from_bytes(&longer).is_err());
    assert!(DeviceCert::from_bytes(&[]).is_err());
}

// --- fingerprints ---

#[test]
fn a_fingerprint_is_twelve_groups_of_five_digits() {
    let fp = Identity::generate()
        .unwrap()
        .public()
        .fingerprint()
        .to_string();
    let groups: Vec<&str> = fp.split(' ').collect();
    assert_eq!(groups.len(), 12);
    assert!(
        groups
            .iter()
            .all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit()))
    );
}

#[test]
fn different_identities_have_different_fingerprints() {
    let a = Identity::generate().unwrap().public().fingerprint();
    let b = Identity::generate().unwrap().public().fingerprint();
    assert_ne!(a, b);
}

// --- environment item ids ---

#[test]
fn environment_ids_ignore_environment_case_but_not_key_case() {
    let key = VaultKey::generate().unwrap();
    let vault = VaultId::generate().unwrap();
    let id = |env, name| ItemId::for_env_secret(&key, vault, env, name).unwrap();

    assert_eq!(id("prod", "API_KEY"), id("PROD", "API_KEY"));
    assert_ne!(id("prod", "API_KEY"), id("prod", "api_key"));
    assert_ne!(id("prod", "API_KEY"), id("dev", "API_KEY"));
}

/// Length prefixes keep the boundary between environment and key unambiguous.
#[test]
fn environment_ids_do_not_collide_across_the_boundary() {
    let key = VaultKey::generate().unwrap();
    let vault = VaultId::generate().unwrap();
    let id = |env, name| ItemId::for_env_secret(&key, vault, env, name).unwrap();
    assert_ne!(id("ab", "C"), id("a", "BC"));
}

#[test]
fn environment_ids_differ_between_vaults_and_keys() {
    let key = VaultKey::generate().unwrap();
    let other_key = VaultKey::generate().unwrap();
    let v1 = VaultId::generate().unwrap();
    let v2 = VaultId::generate().unwrap();
    let a = ItemId::for_env_secret(&key, v1, "prod", "K").unwrap();
    assert_ne!(a, ItemId::for_env_secret(&key, v2, "prod", "K").unwrap());
    assert_ne!(
        a,
        ItemId::for_env_secret(&other_key, v1, "prod", "K").unwrap()
    );
}

/// Ids must survive rotation, so only the first epoch's key may derive them.
#[test]
fn environment_ids_come_only_from_the_first_epoch() {
    let rotated = VaultKey::generate().unwrap().rotate().unwrap();
    let vault = VaultId::generate().unwrap();
    assert!(ItemId::for_env_secret(&rotated, vault, "prod", "K").is_err());
}

// --- invites ---

struct Inviter {
    device: Device,
    cert: DeviceCert,
    vault: VaultId,
}

fn inviter() -> Inviter {
    let identity = Identity::generate().unwrap();
    let device = Device::generate().unwrap();
    let cert = identity.certify(device.public(), NOW);
    Inviter {
        device,
        cert,
        vault: VaultId::generate().unwrap(),
    }
}

fn invite_from(i: &Inviter, relay: &str) -> Result<Invite, Error> {
    Invite::create(
        i.vault,
        relay,
        i.cert.clone(),
        "Ada",
        "acme",
        i.device.public().clone(),
        NOW,
        NOW + DAY,
    )
}

fn joiner() -> (Device, DeviceCert) {
    let identity = Identity::generate().unwrap();
    let device = Device::generate().unwrap();
    let cert = identity.certify(device.public(), NOW);
    (device, cert)
}

#[test]
fn an_invite_round_trips_through_its_link() {
    let i = inviter();
    let invite = invite_from(&i, "https://relay.example").unwrap();
    let link = invite.to_link();
    assert!(link.starts_with(LINK_PREFIX));
    assert_eq!(Invite::from_link(&link, NOW).unwrap(), invite);
    // Whitespace from a chat paste is tolerated.
    assert_eq!(
        Invite::from_link(&format!("  {link}\n"), NOW).unwrap(),
        invite
    );
}

#[test]
fn each_invite_has_its_own_secret_and_mailbox() {
    let i = inviter();
    let a = invite_from(&i, "https://relay.example").unwrap();
    let b = invite_from(&i, "https://relay.example").unwrap();
    assert_ne!(a.secret(), b.secret());
    assert_ne!(a.mailbox_id().unwrap(), b.mailbox_id().unwrap());
}

#[test]
fn an_expired_invite_is_refused() {
    let err = Invite::from_link(LINK, NOW + DAY).unwrap_err();
    assert_eq!(err, Error::Invite("this invite has expired"));
}

#[test]
fn an_invite_cannot_be_made_to_last_longer_than_seven_days() {
    let i = inviter();
    let make = |expires| {
        Invite::create(
            i.vault,
            "https://relay.example",
            i.cert.clone(),
            "Ada",
            "acme",
            i.device.public().clone(),
            NOW,
            expires,
        )
    };
    assert!(make(NOW + MAX_INVITE_LIFETIME_MS).is_ok());
    assert!(make(NOW + MAX_INVITE_LIFETIME_MS + 1).is_err());
    assert!(make(NOW).is_err());
}

/// Same host rule as the relay setting: plain http is for this machine only,
/// and the host is parsed rather than searched for.
#[test]
fn only_https_or_loopback_relays_are_accepted() {
    for ok in [
        "https://relay.example",
        "http://127.0.0.1:8787",
        "http://localhost:8787/",
        "http://[::1]:9000",
    ] {
        assert!(relay_url_allowed(ok), "{ok} was refused");
    }
    for bad in [
        "http://relay.example",
        "http://localhost.evil.example/",
        "http://evil.example/#127.0.0.1",
        "http://evil.example/?r=localhost",
        "ftp://relay.example",
        "https://",
        "relay.example",
    ] {
        assert!(!relay_url_allowed(bad), "{bad} was accepted");
    }
    let i = inviter();
    assert!(invite_from(&i, "http://relay.example").is_err());
}

#[test]
fn names_that_render_as_something_else_are_refused() {
    let i = inviter();
    for name in ["", "   ", "Ada\nAdmin", "Ada\u{202E}nimda", &"x".repeat(65)] {
        let made = Invite::create(
            i.vault,
            "https://relay.example",
            i.cert.clone(),
            name,
            "acme",
            i.device.public().clone(),
            NOW,
            NOW + DAY,
        );
        assert!(made.is_err(), "{name:?} was accepted");
    }
}

#[test]
fn a_damaged_link_is_refused() {
    // Not a link at all.
    assert!(Invite::from_link("https://example.com", NOW).is_err());
    // One character changed in the middle: caught by the checksum.
    let mut chars: Vec<char> = LINK.chars().collect();
    let mid = LINK_PREFIX.len() + 40;
    chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
    let damaged: String = chars.into_iter().collect();
    assert_eq!(
        Invite::from_link(&damaged, NOW).unwrap_err(),
        Error::Invite("this invite link is damaged")
    );
    // Truncated.
    assert!(Invite::from_link(&LINK[..LINK.len() - 10], NOW).is_err());
}

/// The checksum is not a MAC: someone who recomputes it can alter an invite.
/// What they cannot do is swap in a certificate the identity did not sign.
#[test]
fn a_recomputed_checksum_does_not_let_a_forged_certificate_through() {
    use data_encoding::BASE64URL_NOPAD;
    let i = inviter();
    let invite = invite_from(&i, "https://relay.example").unwrap();
    let encoded = invite.to_link();
    let mut body = BASE64URL_NOPAD
        .decode(encoded.strip_prefix(LINK_PREFIX).unwrap().as_bytes())
        .unwrap();
    body.truncate(body.len() - 4);

    // The certificate starts after tag, vault id, and the length-prefixed URL.
    let cert_at = 1 + 16 + 4 + "https://relay.example".len() + 4;
    // Flip a byte of the device signing key inside the certificate.
    body[cert_at + 1 + 32 + 16] ^= 0x01;
    let check = blake3::hash(&body);
    body.extend_from_slice(&check.as_bytes()[..4]);
    let forged = format!("{LINK_PREFIX}{}", BASE64URL_NOPAD.encode(&body));

    assert_eq!(
        Invite::from_link(&forged, NOW).unwrap_err(),
        Error::Invite("the inviter's certificate does not verify")
    );
}

// --- join requests ---

#[test]
fn a_join_request_opens_for_the_inviter() {
    let i = inviter();
    let invite = invite_from(&i, "https://relay.example").unwrap();
    let (device, cert) = joiner();

    let sealed = JoinRequest::seal(&invite, &device, &cert, " Grace ").unwrap();
    let opened = JoinRequest::open(&i.device, i.vault, invite.secret(), &sealed).unwrap();
    assert_eq!(opened.cert(), &cert);
    assert_eq!(opened.name(), "Grace");
}

#[test]
fn a_join_request_does_not_open_without_the_invite_secret() {
    let i = inviter();
    let invite = invite_from(&i, "https://relay.example").unwrap();
    let (device, cert) = joiner();
    let sealed = JoinRequest::seal(&invite, &device, &cert, "Grace").unwrap();

    let wrong = InviteSecret::generate().unwrap();
    assert_eq!(
        JoinRequest::open(&i.device, i.vault, &wrong, &sealed).unwrap_err(),
        Error::Decrypt
    );
}

/// A relay knows the mailbox id and the inviter's public keys — everything in
/// the invite except the secret. That is not enough to forge a request.
#[test]
fn a_relay_cannot_inject_its_own_join_request() {
    let i = inviter();
    let invite = invite_from(&i, "https://relay.example").unwrap();

    // The relay builds an invite with the same public parts and its own secret.
    let relays_guess = invite_from(&i, "https://relay.example").unwrap();
    let (device, cert) = joiner();
    let forged = JoinRequest::seal(&relays_guess, &device, &cert, "Mallory").unwrap();

    assert_eq!(
        JoinRequest::open(&i.device, i.vault, invite.secret(), &forged).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn a_join_request_cannot_be_replayed_into_another_invite() {
    let i = inviter();
    let first = invite_from(&i, "https://relay.example").unwrap();
    let second = invite_from(&i, "https://relay.example").unwrap();
    let (device, cert) = joiner();
    let sealed = JoinRequest::seal(&first, &device, &cert, "Grace").unwrap();

    assert!(JoinRequest::open(&i.device, i.vault, second.secret(), &sealed).is_err());
    // Nor into another vault under the same secret.
    let other_vault = VaultId::generate().unwrap();
    assert!(JoinRequest::open(&i.device, other_vault, first.secret(), &sealed).is_err());
}

#[test]
fn only_the_inviting_device_can_open_a_request() {
    let i = inviter();
    let invite = invite_from(&i, "https://relay.example").unwrap();
    let (device, cert) = joiner();
    let sealed = JoinRequest::seal(&invite, &device, &cert, "Grace").unwrap();

    let bystander = Device::generate().unwrap();
    assert!(JoinRequest::open(&bystander, i.vault, invite.secret(), &sealed).is_err());
}

#[test]
fn flipping_any_byte_of_a_join_request_is_refused() {
    let i = inviter();
    let invite = invite_from(&i, "https://relay.example").unwrap();
    let (device, cert) = joiner();
    let sealed = JoinRequest::seal(&invite, &device, &cert, "Grace").unwrap();

    for at in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[at] ^= 0x01;
        assert!(
            JoinRequest::open(&i.device, i.vault, invite.secret(), &tampered).is_err(),
            "byte {at} could be altered without detection"
        );
    }
}

#[test]
fn a_device_cannot_seal_a_request_with_someone_elses_certificate() {
    let i = inviter();
    let invite = invite_from(&i, "https://relay.example").unwrap();
    let (device, _) = joiner();
    let (_, someone_elses) = joiner();
    assert!(JoinRequest::seal(&invite, &device, &someone_elses, "Grace").is_err());
}

/// Someone holding the link, sealing correctly with their own device key but
/// carrying another person's (public) certificate, must still be refused: the
/// request proves possession of the certified device's key.
#[test]
fn a_request_carrying_a_certificate_for_another_device_is_refused() {
    type Aead = hpke::aead::ChaCha20Poly1305;
    type Kdf = hpke::kdf::HkdfSha256;
    type Kem = hpke::kem::X25519HkdfSha256;

    let i = inviter();
    let invite = invite_from(&i, "https://relay.example").unwrap();
    let (attacker, _) = joiner();
    let (_, victim_cert) = joiner();

    // What `JoinRequest::seal` does, minus its own refusal.
    let secret = Key32::new(*invite.secret().expose());
    let psk = mortise_crypto::kdf::subkey(&secret, b"truepass/v1/invite-psk").unwrap();
    let mailbox = invite.mailbox_id().unwrap();
    let mut w = Writer::new(Tag::JoinRequest);
    w.bytes(&victim_cert.to_bytes()).bytes(b"Grace");
    let mut aad = i.vault.as_bytes().to_vec();
    aad.extend_from_slice(mailbox.as_bytes());
    let attacker_pk = <Kem as hpke::Kem>::sk_to_pk(attacker.kex_private());
    let (encapped, ct) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
        &hpke::OpModeS::AuthPsk(
            (attacker.kex_private().clone(), attacker_pk),
            hpke::PskBundle::new(psk.expose(), mailbox.as_bytes()).unwrap(),
        ),
        &i.device.public().kex_public().unwrap(),
        b"truepass/v1/join-request",
        &w.finish(),
        &aad,
    )
    .unwrap();
    let mut forged = vec![0x01];
    forged.extend_from_slice(attacker.public().kex_public_bytes());
    forged.extend_from_slice(&encapped.to_bytes());
    forged.extend_from_slice(&ct);

    assert_eq!(
        JoinRequest::open(&i.device, i.vault, invite.secret(), &forged).unwrap_err(),
        Error::Signature
    );

    // Claiming to be the victim's key in the header does not help either: the
    // seal was made with the attacker's key, so AuthPSK fails to open.
    forged[1..33].copy_from_slice(victim_cert.device().kex_public_bytes());
    assert!(JoinRequest::open(&i.device, i.vault, invite.secret(), &forged).is_err());
}
