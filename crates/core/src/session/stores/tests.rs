//! Property tests: random operation sequences against a model, with
//! periodic close/reopen from disk (crash-recovery shape — committed
//! state must survive; the model is the source of truth).

use super::*;
use crate::store::Db;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KeyPair, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord,
    PreKeyStore, ProtocolAddress, PublicKey, SessionRecord, SessionStore, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};
use proptest::prelude::*;
use std::collections::HashMap;

const NS: &str = "prop";

#[derive(Clone, Debug)]
enum Op {
    SavePreKey(u8),
    RemovePreKey(u8),
    SaveSignedPreKey(u8),
    SaveKyber(u8),
    MarkKyberUsed(u8, u8, u8),
    SaveSession(u8),
    SaveIdentity(u8, u8),
    Reopen,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u8..4).prop_map(Op::SavePreKey),
        1 => (0u8..4).prop_map(Op::RemovePreKey),
        2 => (0u8..4).prop_map(Op::SaveSignedPreKey),
        2 => (0u8..4).prop_map(Op::SaveKyber),
        2 => (0u8..4, 0u8..2, 0u8..3).prop_map(|(a, b, c)| Op::MarkKyberUsed(a, b, c)),
        3 => (0u8..4).prop_map(Op::SaveSession),
        2 => (0u8..4, 0u8..3).prop_map(|(a, b)| Op::SaveIdentity(a, b)),
        1 => Just(Op::Reopen),
    ]
}

struct Fixtures {
    pre_keys: Vec<PreKeyRecord>,
    signed_pre_keys: Vec<SignedPreKeyRecord>,
    kyber_pre_keys: Vec<KyberPreKeyRecord>,
    sessions: Vec<SessionRecord>,
    identities: Vec<IdentityKey>,
    base_keys: Vec<PublicKey>,
}

impl Fixtures {
    fn generate() -> Self {
        let mut rng = crate::session::csprng();
        let identities: Vec<IdentityKeyPair> = (0..3)
            .map(|_| IdentityKeyPair::generate(&mut rng))
            .collect();
        let pre_keys = (0..4u32)
            .map(|i| PreKeyRecord::new(PreKeyId::from(i), &KeyPair::generate(&mut rng)))
            .collect();
        let signed_pre_keys = (0..4u32)
            .map(|i| {
                let pair = KeyPair::generate(&mut rng);
                let sig = identities[0]
                    .private_key()
                    .calculate_signature(pair.public_key.serialize().as_ref(), &mut rng)
                    .unwrap();
                SignedPreKeyRecord::new(
                    SignedPreKeyId::from(i),
                    Timestamp::from_epoch_millis(0),
                    &pair,
                    &sig,
                )
            })
            .collect();
        let kyber_pre_keys = (0..4u32)
            .map(|i| {
                KyberPreKeyRecord::generate(
                    libsignal_protocol::kem::KeyType::MLKEM1024,
                    KyberPreKeyId::from(i),
                    identities[0].private_key(),
                )
                .unwrap()
            })
            .collect();
        let sessions = (0..4).map(|_| SessionRecord::new_fresh()).collect();
        let base_keys = (0..3)
            .map(|_| KeyPair::generate(&mut rng).public_key)
            .collect();
        Fixtures {
            pre_keys,
            signed_pre_keys,
            kyber_pre_keys,
            sessions,
            identities: identities.iter().map(|p| *p.identity_key()).collect(),
            base_keys,
        }
    }
}

#[derive(Default)]
struct Model {
    pre_keys: HashMap<u8, Vec<u8>>,
    signed_pre_keys: HashMap<u8, Vec<u8>>,
    kyber_pre_keys: HashMap<u8, Vec<u8>>,
    kyber_used: HashMap<u8, Vec<u8>>,
    sessions: HashMap<String, Vec<u8>>,
    identities: HashMap<String, Vec<u8>>,
}

fn addr(i: u8) -> ProtocolAddress {
    ProtocolAddress::new(format!("peer-{i}"), 1u32.try_into().unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn random_ops_match_model(ops in proptest::collection::vec(op_strategy(), 1..60)) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(run_ops(ops));
    }
}

async fn run_ops(ops: Vec<Op>) {
    let fixtures = Fixtures::generate();
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("prop.db");
    let mut db = Db::open(&path, None).unwrap();
    // A local persona must exist for the identity store.
    let mut rng = crate::session::csprng();
    create_local(db.conn(), NS, 7, &IdentityKeyPair::generate(&mut rng)).unwrap();
    let mut model = Model::default();

    for op in ops {
        match op {
            Op::SavePreKey(i) => {
                let rec = &fixtures.pre_keys[i as usize];
                SqlitePreKeyStore {
                    db: db.conn(),
                    namespace: NS.into(),
                }
                .save_pre_key(PreKeyId::from(i as u32), rec)
                .await
                .unwrap();
                model.pre_keys.insert(i, rec.serialize().unwrap());
            }
            Op::RemovePreKey(i) => {
                SqlitePreKeyStore {
                    db: db.conn(),
                    namespace: NS.into(),
                }
                .remove_pre_key(PreKeyId::from(i as u32))
                .await
                .unwrap();
                model.pre_keys.remove(&i);
            }
            Op::SaveSignedPreKey(i) => {
                let rec = &fixtures.signed_pre_keys[i as usize];
                SqliteSignedPreKeyStore {
                    db: db.conn(),
                    namespace: NS.into(),
                }
                .save_signed_pre_key(SignedPreKeyId::from(i as u32), rec)
                .await
                .unwrap();
                model.signed_pre_keys.insert(i, rec.serialize().unwrap());
            }
            Op::SaveKyber(i) => {
                let rec = &fixtures.kyber_pre_keys[i as usize];
                SqliteKyberPreKeyStore {
                    db: db.conn(),
                    namespace: NS.into(),
                }
                .save_kyber_pre_key(KyberPreKeyId::from(i as u32), rec)
                .await
                .unwrap();
                model.kyber_pre_keys.insert(i, rec.serialize().unwrap());
            }
            Op::MarkKyberUsed(id, spk, base) => {
                let base_key = &fixtures.base_keys[base as usize];
                let result = SqliteKyberPreKeyStore {
                    db: db.conn(),
                    namespace: NS.into(),
                }
                .mark_kyber_pre_key_used(
                    KyberPreKeyId::from(id as u32),
                    SignedPreKeyId::from(spk as u32),
                    base_key,
                )
                .await;
                let mut tuple = (spk as u32).to_be_bytes().to_vec();
                tuple.extend_from_slice(base_key.serialize().as_ref());
                match model.kyber_used.get(&id) {
                    // Unknown key id → store must error.
                    _ if !model.kyber_pre_keys.contains_key(&id) => {
                        assert!(result.is_err(), "mark on missing key must fail");
                    }
                    None => {
                        result.unwrap();
                        model.kyber_used.insert(id, tuple);
                    }
                    Some(existing) if *existing == tuple => {
                        result.unwrap();
                    }
                    Some(_) => {
                        assert!(result.is_err(), "reuse with different base must fail");
                    }
                }
            }
            Op::SaveSession(i) => {
                let rec = &fixtures.sessions[i as usize];
                SqliteSessionStore {
                    db: db.conn(),
                    namespace: NS.into(),
                }
                .store_session(&addr(i), rec)
                .await
                .unwrap();
                model
                    .sessions
                    .insert(format!("peer-{i}.1"), rec.serialize().unwrap());
            }
            Op::SaveIdentity(i, variant) => {
                let key = &fixtures.identities[variant as usize];
                let expected_change = model
                    .identities
                    .get(&format!("peer-{i}.1"))
                    .is_some_and(|old| *old != key.serialize().to_vec());
                let change = SqliteIdentityStore {
                    db: db.conn(),
                    namespace: NS.into(),
                }
                .save_identity(&addr(i), key)
                .await
                .unwrap();
                assert_eq!(change == IdentityChange::ReplacedExisting, expected_change);
                model
                    .identities
                    .insert(format!("peer-{i}.1"), key.serialize().to_vec());
            }
            Op::Reopen => {
                drop(db);
                db = Db::open(&path, None).unwrap();
            }
        }

        // After every op: every readable value matches the model.
        for i in 0..4u8 {
            let got = SqlitePreKeyStore {
                db: db.conn(),
                namespace: NS.into(),
            }
            .get_pre_key(PreKeyId::from(i as u32))
            .await
            .ok()
            .map(|r| r.serialize().unwrap());
            assert_eq!(got, model.pre_keys.get(&i).cloned(), "prekey {i}");

            let got = SqliteSignedPreKeyStore {
                db: db.conn(),
                namespace: NS.into(),
            }
            .get_signed_pre_key(SignedPreKeyId::from(i as u32))
            .await
            .ok()
            .map(|r| r.serialize().unwrap());
            assert_eq!(got, model.signed_pre_keys.get(&i).cloned(), "spk {i}");

            let got = SqliteKyberPreKeyStore {
                db: db.conn(),
                namespace: NS.into(),
            }
            .get_kyber_pre_key(KyberPreKeyId::from(i as u32))
            .await
            .ok()
            .map(|r| r.serialize().unwrap());
            assert_eq!(got, model.kyber_pre_keys.get(&i).cloned(), "kyber {i}");

            let got = SqliteSessionStore {
                db: db.conn(),
                namespace: NS.into(),
            }
            .load_session(&addr(i))
            .await
            .unwrap()
            .map(|r| r.serialize().unwrap());
            assert_eq!(
                got,
                model.sessions.get(&format!("peer-{i}.1")).cloned(),
                "session {i}"
            );

            let got = SqliteIdentityStore {
                db: db.conn(),
                namespace: NS.into(),
            }
            .get_identity(&addr(i))
            .await
            .unwrap()
            .map(|k| k.serialize().to_vec());
            assert_eq!(
                got,
                model.identities.get(&format!("peer-{i}.1")).cloned(),
                "identity {i}"
            );

            // TOFU: stored identity trusts itself, distrusts others.
            for (v, key) in fixtures.identities.iter().enumerate() {
                let trusted = SqliteIdentityStore {
                    db: db.conn(),
                    namespace: NS.into(),
                }
                .is_trusted_identity(&addr(i), key, Direction::Sending)
                .await
                .unwrap();
                let expected = match model.identities.get(&format!("peer-{i}.1")) {
                    None => true,
                    Some(stored) => *stored == key.serialize().to_vec(),
                };
                assert_eq!(trusted, expected, "trust i={i} variant={v}");
            }
        }
    }
}
