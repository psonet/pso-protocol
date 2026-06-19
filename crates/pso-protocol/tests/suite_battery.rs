//! One generic battery, run against two suites. The battery never names
//! a curve, hash, signature, or KDF — only `S: Suite`. That it passes for
//! both `PsoV1` (Poseidon) and `Mock` (additive hash + additive-challenge
//! Schnorr + additive KDF) is the proof that the protocol is pluggable:
//! swap a primitive, the same tests still hold.
//!
//! This core battery exercises only the core-crate seams: the owner
//! commitment, entity hashing, binding/KDF, and the NFT key-derivation
//! axis (consent box + local issuance). The concrete circuit/witness types
//! and their round-trips live in `pso-zk-canonical`, tested there.
//!
//! The concrete entity types live in consumer crates, so the battery
//! carries its own minimal generic entity (`TestNft`) to drive the
//! protocol.

use ark_ff::One;
use ark_std::rand::Rng;
use ark_std::UniformRand;

use pso_protocol::error::Error;
use pso_protocol::primitive::kdf::Kdf;
use pso_protocol::primitive::signature::{EmbeddedSignature, SignatureScheme};
use pso_protocol::protocol::entity::{Entity, Owned};
use pso_protocol::protocol::key::{NftSigner, Signer};
use pso_protocol::{PsoV1, Suite};

use mock::Mock;

/// Test-only insecure scaffolding: an additive hash, an additive KDF, and a
/// `Mock` suite that wires them in (same curve, same formulas as `PsoV1`).
/// Proves the protocol and battery are generic over `Hash`/`Signature`/`Kdf`.
/// INSECURE — never use in production.
mod mock {
    use ark_ff::PrimeField;

    use pso_protocol::error::Error;
    use pso_protocol::primitive::curve::Grumpkin;
    use pso_protocol::primitive::exchange::EcdhEmbedded;
    use pso_protocol::primitive::hash::FieldHasher;
    use pso_protocol::primitive::kdf::Kdf;
    use pso_protocol::primitive::signature::Schnorr;
    use pso_protocol::Suite;

    /// Insecure additive hash for pluggability tests. Never use in production.
    pub struct AddHash;

    impl<F: PrimeField> FieldHasher<F> for AddHash {
        fn hash(inputs: &[F]) -> Result<F, Error> {
            // Position-weighted sum + length, so order and arity matter.
            let mut acc = F::from(inputs.len() as u64);
            for (i, x) in inputs.iter().enumerate() {
                acc += *x * F::from((i as u64) + 1);
            }
            Ok(acc)
        }
    }

    /// Insecure additive KDF for pluggability tests.
    pub struct AddKdf;

    impl<F: PrimeField> Kdf<F> for AddKdf {
        const DOMAIN: &'static str = "PSO/kdf/add/test";
        fn derive(inputs: &[F]) -> Result<F, Error> {
            AddHash::hash(inputs)
        }
    }

    /// Insecure suite for pluggability tests only.
    pub struct Mock;

    impl Suite for Mock {
        type Field = ark_bn254::Fr;
        type Curve = Grumpkin;
        type Hash = AddHash;
        type Signature = Schnorr<Grumpkin>;
        type Kdf = AddKdf;
        type Exchange = EcdhEmbedded<Grumpkin>;
    }
}

/// Minimal owned entity for exercising the generic protocol: a stored id
/// seed and a flat body. The real entity types live in `pso-integration`.
struct TestNft<S: Suite> {
    id: S::Field,
    owner: S::Field,
    fields: Vec<S::Field>,
}

impl<S: Suite> Entity<S> for TestNft<S> {
    fn id_seed(&self) -> Result<S::Field, Error> {
        Ok(self.id)
    }
    fn encode_id_body(&self, _out: &mut Vec<S::Field>) -> Result<(), Error> {
        Ok(())
    }
    fn encode_body(&self, out: &mut Vec<S::Field>) -> Result<(), Error> {
        out.extend_from_slice(&self.fields);
        Ok(())
    }
}
impl<S: Suite> Owned<S> for TestNft<S> {
    fn owner(&self) -> Result<S::Field, Error> {
        Ok(self.owner)
    }
}

fn sample_body<S: Suite, R: Rng>(rng: &mut R) -> Vec<S::Field> {
    vec![
        S::Field::from(978u64),   // currency
        S::Field::from(1_000u64), // base
        S::Field::from(42u64),    // atto
        S::Field::rand(rng),      // suId
        S::Field::rand(rng),      // suId
    ]
}

fn sample_nft<S: Suite, R: Rng>(rng: &mut R, owner: S::Field) -> TestNft<S> {
    TestNft {
        id: owner,
        owner,
        fields: sample_body::<S, _>(rng),
    }
}

fn battery<S: Suite>()
where
    S::Signature: EmbeddedSignature<S::Curve>,
{
    let mut rng = ark_std::test_rng();

    // --- owner commitment: deterministic + sensitive to nonce ---
    let (_sk, pk) = S::Signature::keypair(&mut rng);
    let nonce = S::Field::rand(&mut rng);
    let owner = S::derive_owner(&pk, nonce).unwrap();
    assert_eq!(
        owner,
        S::derive_owner(&pk, nonce).unwrap(),
        "owner not deterministic"
    );
    let owner2 = S::derive_owner(&pk, nonce + S::Field::one()).unwrap();
    assert_ne!(owner, owner2, "owner not sensitive to nonce");

    // --- entity hash: deterministic + sensitive to body ---
    let td = sample_nft::<S, _>(&mut rng, owner);
    let h1 = td.entity_hash().unwrap();
    assert_eq!(
        h1,
        td.entity_hash().unwrap(),
        "entity hash not deterministic"
    );
    assert_eq!(Owned::<S>::owner(&td).unwrap(), owner);
    let td_other = sample_nft::<S, _>(&mut rng, owner); // different random suIds
    assert_ne!(
        h1,
        td_other.entity_hash().unwrap(),
        "entity hash not sensitive to body"
    );

    // --- binding + KDF are reachable and deterministic ---
    let binding = S::binding(&[7u8; 20], &[9u8; 32], 1234).unwrap();
    assert_eq!(binding, S::binding(&[7u8; 20], &[9u8; 32], 1234).unwrap());
    let k = S::Kdf::derive(&[nonce, owner]).unwrap();
    assert_eq!(
        k,
        S::Kdf::derive(&[nonce, owner]).unwrap(),
        "kdf not deterministic"
    );

    key_origins::<S>(&mut rng);
}

/// The NFT key-derivation axis: the consent-box CryptoBox round-trip and
/// local self-issuance. Generic over the suite (and thus over curve,
/// hash, KDF). `Ecdh` runs the box on the embedded curve.
fn key_origins<S>(rng: &mut impl Rng)
where
    S: Suite,
    S::Signature: EmbeddedSignature<S::Curve>,
{
    // Client holds a consent keypair.
    let (consent_sk, consent_pk) = S::random_keypair(rng);

    // Server: derive nft_sk via the box, destroy it, ship opaque_pk + seed.
    let (server_seed, opaque_pk) = S::issue_for_remote(rng, &consent_pk).unwrap();
    let owner_server = server_seed.derive_owner().unwrap();

    // Client: reconstruct the signer from (consent_sk, opaque_pk, nonce).
    let client = S::signer_from_remote(&consent_sk, &opaque_pk, server_seed.nonce).unwrap();

    // The reconstructed key reproduces the server's public key …
    assert_eq!(
        client.public_key(),
        server_seed.pk,
        "consent-box: client could not reconstruct nft_pk"
    );
    // … and therefore the same derivedOwner.
    let owner_client = S::derive_owner(&client.public_key(), server_seed.nonce).unwrap();
    assert_eq!(
        owner_server, owner_client,
        "consent-box: derivedOwner mismatch"
    );

    // A wrong consent secret must NOT reconstruct the key.
    let (other_sk, _) = S::random_keypair(rng);
    let wrong = S::signer_from_remote(&other_sk, &opaque_pk, server_seed.nonce).unwrap();
    assert_ne!(
        wrong.public_key(),
        server_seed.pk,
        "consent-box: wrong key reconstructed"
    );

    // Local self-issuance: the stored seed pk matches the key the signer holds.
    let local = Signer::<S>::local(rng).unwrap();
    assert_eq!(
        local.secret().public_key().unwrap(),
        local.owner_seed().pk,
        "local: pk mismatch"
    );
}

#[test]
fn pso_suite() {
    battery::<PsoV1>();
}

#[test]
fn mock_suite() {
    battery::<Mock>();
}
