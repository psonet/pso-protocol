//! Parity vectors for the fingerprint-service epoch encoding.
//!
//! `tests/fixtures/fs_epoch_parity.json` is the shared contract between this
//! crate and the L2 contracts: the Solidity side recomputes every vector's
//! `canonical` and `digest` from the same inputs with `abi.encodePacked` +
//! `keccak256`. The default run asserts every vector in the file; a run with
//! `PSO_REGEN_PARITY=1` first rewrites the file from [`vectors`] and then runs
//! the same assertions against it. Every run compares the file to [`vectors`]
//! rendered afresh, so editing the vectors without regenerating the file fails
//! the test. Because the digests are what the contracts accept on-chain,
//! regenerating the file is a deliberate, reviewed change, never a side
//! effect of a test run.

use std::path::PathBuf;

use pso_protocol::protocol::fs_epoch::{FsEpoch, G2_EIP2537_LEN};
use serde_json::{json, Value};

const SCHEMA_VERSION: u64 = 1;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fs_epoch_parity.json")
}

fn hex(bytes: &[u8]) -> String {
    let body: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{body}")
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    let s = s.strip_prefix("0x").expect("0x prefix");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    unhex(v).try_into().expect("fixed-length hex")
}

/// The vectors in chain order: each successor's `prev_hash` is its
/// predecessor's digest. The genesis entry has epoch 0 and a zero
/// `prev_hash`; the chain covers a one-byte and a 255-byte `dst`. Every
/// `pk_att` is a padded EIP-2537 encoding: 16 zero bytes lead each 64-byte
/// limb.
fn vectors() -> Vec<FsEpoch> {
    let pk = |seed: u8| -> [u8; G2_EIP2537_LEN] {
        core::array::from_fn(|i| {
            if i % 64 < 16 {
                0
            } else {
                (i as u8).wrapping_mul(seed).wrapping_add(seed)
            }
        })
    };
    let genesis = FsEpoch::new(
        0,
        pk(3),
        b"PSO-FS-ATT-V1".to_vec(),
        20260101,
        [0x11; 32],
        [0; 32],
    )
    .unwrap();
    let mut chain = vec![genesis];
    let successors = [
        (1, pk(5), vec![0x01], 20260401, [0x22; 32]),
        (
            2,
            pk(7),
            (1..=u8::MAX).collect::<Vec<u8>>(),
            20260701,
            [0x33; 32],
        ),
        (
            3,
            pk(11),
            b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_".to_vec(),
            20261001,
            [0x44; 32],
        ),
    ];
    for (epoch, pk_att, dst, start_wwd, members_hash) in successors {
        let prev_hash = chain.last().unwrap().digest();
        chain.push(FsEpoch::new(epoch, pk_att, dst, start_wwd, members_hash, prev_hash).unwrap());
    }
    chain
}

fn render(chain: &[FsEpoch]) -> Value {
    let vectors: Vec<Value> = chain
        .iter()
        .map(|e| {
            json!({
                "epoch": e.epoch(),
                "pk_att": hex(e.pk_att()),
                "dst": hex(e.dst()),
                "start_wwd": e.start_wwd(),
                "members_hash": hex(e.members_hash()),
                "prev_hash": hex(e.prev_hash()),
                "canonical": hex(&e.canonical_bytes()),
                "digest": hex(&e.digest()),
            })
        })
        .collect();
    json!({
        "comment": "Fingerprint-service epoch encoding vectors: canonical = \
                    version(u8=1) | epoch(u32 BE) | pk_att(256) | len(dst)(u8) | dst \
                    | start_wwd(u32 BE) | members_hash(32) | prev_hash(32); \
                    digest = keccak256(canonical). Vectors form a chain: each \
                    prev_hash is the preceding vector's digest. The L2 contracts' \
                    parity test consumes this file; regenerating it changes \
                    on-chain hashes.",
        "schema_version": SCHEMA_VERSION,
        "vectors": vectors,
    })
}

#[test]
fn fixture_matches_the_encoding() {
    let path = fixture_path();
    if std::env::var_os("PSO_REGEN_PARITY").is_some() {
        let mut text = serde_json::to_string_pretty(&render(&vectors())).unwrap();
        text.push('\n');
        std::fs::write(&path, text).unwrap();
    }

    let text = std::fs::read_to_string(&path).unwrap();
    let file: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        file,
        render(&vectors()),
        "fixture is stale; regenerate with PSO_REGEN_PARITY=1"
    );
    assert_eq!(file["schema_version"], SCHEMA_VERSION);
    let vectors = file["vectors"].as_array().expect("vectors array");
    assert!(vectors.len() >= 4, "at least four vectors");

    let mut prev_digest = [0u8; 32];
    for (i, v) in vectors.iter().enumerate() {
        let entry = FsEpoch::new(
            v["epoch"].as_u64().unwrap().try_into().unwrap(),
            arr(&v["pk_att"]),
            unhex(&v["dst"]),
            v["start_wwd"].as_u64().unwrap().try_into().unwrap(),
            arr(&v["members_hash"]),
            arr(&v["prev_hash"]),
        )
        .unwrap();
        let canonical = entry.canonical_bytes();
        let digest = entry.digest();
        assert_eq!(canonical, unhex(&v["canonical"]), "vector {i} canonical");
        assert_eq!(digest, arr::<32>(&v["digest"]), "vector {i} digest");
        assert_eq!(
            FsEpoch::decode(&canonical).unwrap(),
            entry,
            "vector {i} decode"
        );
        assert_eq!(
            entry.prev_hash(),
            &prev_digest,
            "vector {i} chains to {}",
            i.wrapping_sub(1)
        );
        prev_digest = digest;
    }
    assert_eq!(vectors[0]["epoch"], 0);
    assert!(vectors.iter().any(|v| unhex(&v["dst"]).len() == 1));
    assert!(vectors.iter().any(|v| unhex(&v["dst"]).len() == 255));
}
