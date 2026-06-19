# pso-protocol-derive

[![crates.io](https://img.shields.io/crates/v/pso-protocol-derive.svg)](https://crates.io/crates/pso-protocol-derive)
[![release](https://img.shields.io/github/v/release/psonet/pso-protocol.svg)](https://github.com/psonet/pso-protocol/releases)
[![CI](https://github.com/psonet/pso-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/psonet/pso-protocol/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

`#[derive(Entity)]` for [`pso-protocol`](../pso-protocol) — give a typed NFT
struct its `Entity` (and optionally `Owned`) impl from per-field `#[pso(...)]`
roles, so the canonical hash preimage is read off the struct definition instead
of a hand-built `Vec<Field>`. Published alongside `pso-protocol` at the same
version.

## Architecture

The macro emits, generic over `S: Suite`:

- `impl Entity<S>` — `id_seed()`, `encode_id_body()`, `encode_body()`. The
  protocol's default `entity_hash()` folds them: `id = H(id_seed, id_body…)`,
  then `hash = H(id, body…)`.
- `impl Owned<S>` — `owner()`, emitted only when a field carries the `owner`
  role.

Field types must implement the encoding seam: `FieldElement<S::Field>` for the
single-element roles (`id_seed`, `owner`) and `FieldEncode<S::Field>` for the
fold roles (`id_body`, `body`) — a `uint256`, for instance, encodes to two limbs
`[lo, hi]`. The `alloy` feature on `pso-protocol` provides these impls for
`Address` / `U256` / `B256`.

### Field roles

Every field must carry exactly one `#[pso(...)]` attribute — a consensus
preimage must never silently omit a field.

| Role | Meaning |
| ---- | ------- |
| `#[pso(id_seed)]` | Exactly one field; seeds the id accumulator. Must be a single element. |
| `#[pso(id_body)]` | Folded onto the seed to form the id. |
| `#[pso(body)]` | The entity body, folded from the id. |
| `#[pso(owner)]` | Marks the stored `derivedOwner`; emits the `Owned` impl. Single element; combine with `body`. |
| `#[pso(skip)]` | Explicitly excluded from the hash preimage. |
| `#[pso(pos = N)]` | Explicit fold position within the field's group (`body` or `id_body`). All-or-nothing per group; positions must be unique. Lets a struct mirroring a `sol!` layout fold in the protocol's canonical order regardless of declaration order. (`position` is an accepted alias.) |

The struct must have named fields and no generic parameters — the suite `S` is
introduced by the generated impl.

## Usage

```toml
[dependencies]
pso-protocol = "0.8"
pso-protocol-derive = "0.8"
```

```rust
use pso_protocol::{PsoV1, protocol::entity::{Entity, Owned}};
use pso_protocol_derive::Entity;
use alloy_primitives::{Address, B256, U256};   // needs pso-protocol's `alloy` feature

#[derive(Entity)]
struct SpendingUnit {
    #[pso(id_seed)]              id: B256,
    #[pso(body, owner, pos = 0)] derived_owner: B256,
    #[pso(body, pos = 1)]        attester: Address,
    #[pso(body, pos = 5)]        base: U256,      // folds as [lo, hi]
    #[pso(skip)]                 cached_hash: B256,
}

let su = SpendingUnit { /* … */ };
let hash  = Entity::<PsoV1>::entity_hash(&su)?;
let owner = Owned::<PsoV1>::owner(&su)?;
```

Declaration order is the fold order when no field sets `pos`; otherwise each
group is sorted by `pos`. Missing a `#[pso(...)]` on any field is a compile
error (use `#[pso(skip)]` to exclude it intentionally).

## Verifying releases

Releases ship sigstore cosign signatures + SLSA build-provenance attestations for every published `.crate`. See [SECURITY.md](../../SECURITY.md) for the threat model and the copy-pasteable verify recipe.

Quick check:

```sh
TAG=v0.8.0
ARTIFACT=pso-protocol-derive-${TAG#v}.crate
gh release download "$TAG" --repo psonet/pso-protocol \
  --pattern "$ARTIFACT" --pattern "$ARTIFACT.sig" --pattern "$ARTIFACT.pem"
cosign verify-blob \
  --certificate "$ARTIFACT.pem" --signature "$ARTIFACT.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/psonet/pso-protocol/\.github/workflows/ci\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARTIFACT"
```

## License

[MIT](../../LICENSE) — same as `pso-protocol`.
