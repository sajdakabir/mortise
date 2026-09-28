//! Measures the real unlock cost. Spec §10 requires this before the Argon2
//! parameters are frozen.
use std::time::Instant;
use truepass_crypto::kdf::{self, Argon2Params};
use truepass_crypto::secret::Key32;

fn main() {
    let salt = [0x42u8; 16];
    let ak = Key32::new([0x11u8; 32]);
    let pw = b"correct horse battery staple";

    for (label, p) in [
        (
            "OWASP floor  (19MiB, t=2, p=1)",
            Argon2Params {
                m_cost_kib: 19 * 1024,
                t_cost: 2,
                p_cost: 1,
            },
        ),
        ("spec default (64MiB, t=3, p=4)", Argon2Params::default()),
        (
            "conservative (128MiB,t=4, p=4)",
            Argon2Params {
                m_cost_kib: 128 * 1024,
                t_cost: 4,
                p_cost: 4,
            },
        ),
    ] {
        let mut best = f64::MAX;
        for _ in 0..3 {
            let t0 = Instant::now();
            let _ = kdf::unlock(pw, &ak, &salt, p).unwrap();
            best = best.min(t0.elapsed().as_secs_f64() * 1000.0);
        }
        println!("{label}  ->  {best:7.1} ms");
    }
}
