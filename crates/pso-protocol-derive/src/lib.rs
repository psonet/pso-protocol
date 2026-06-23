//! `#[derive(Entity)]` — give a typed NFT struct its
//! [`pso_protocol::protocol::entity::Entity`] (and optionally `Owned`)
//! impl from per-field `#[pso(...)]` roles, so the canonical hash
//! preimage is read off the struct definition instead of a hand-built
//! `Vec<Field>`.
//!
//! Each named field declares one or more roles:
//!
//! - `#[pso(id_seed)]` — exactly one field; seeds the id accumulator.
//!   Must encode to a single element (`FieldElement`).
//! - `#[pso(id_body)]` — folded onto the seed to form the id.
//! - `#[pso(body)]`    — the entity body, folded from the id.
//!
//! A `body` / `id_body` field of type `Vec<T>` is hashed as a canonical
//! **set**: it folds as `[ len, e₀, e₁, … ]` with the elements strictly
//! ascending by field value (see
//! [`pso_protocol::codec::SortedSet`]). The element `T` must be a
//! single [`pso_protocol::FieldElement`], and the caller must supply the
//! vector already sorted + de-duplicated (an out-of-order or duplicate entry
//! is rejected at hash time with `Error::UnsortedSet`). The length prefix
//! removes the adjacent-vector boundary collision, and the strict ordering
//! makes the hash independent of the producer's vector order.
//! - `#[pso(owner)]`   — marks the stored `derivedOwner`; emits an
//!   `Owned` impl. Must be a `FieldElement`. Combine with `body`.
//! - `#[pso(skip)]`    — explicitly excluded from the hash preimage.
//! - `#[pso(pos = N)]` — explicit fold position within its group (`body`
//!   or `id_body`). When present, that group is sorted by `N` instead of
//!   following declaration order — so a struct mirroring a `sol!` layout
//!   can fold its fields in the protocol's canonical order regardless of
//!   how the fields are declared. `pos` is all-or-nothing per group, and
//!   positions must be unique. (`position` is accepted as an alias.)
//! - `#[pso(limbed)]` — mark a *scalar* field as **limbed**: it folds through
//!   [`pso_protocol::FieldEncode`] to the multiple field elements its type
//!   needs (e.g. a `uint256` → `[lo, hi]`). Without `limbed` a scalar is
//!   **single** — it folds to exactly one [`pso_protocol::FieldElement`] (the
//!   safe default; a wide type used without `limbed` has no `FieldElement`
//!   impl and fails to build). The limb *count* is a property of the type, so
//!   the flag carries intent only, not a number. `limbed` is rejected on a
//!   `Vec<T>` field (already a set of single-element items).
//!
//! Every field must carry a `#[pso(...)]` attribute: a consensus preimage
//! must not silently omit a field. The struct must have named fields and
//! no generic parameters (the suite `S` is introduced by the impl).
//!
//! ```ignore
//! #[derive(Entity)]
//! struct SpendingUnit {
//!     #[pso(id_seed)]            su_id: Bytes32,
//!     #[pso(body, owner, pos=0)] derived_owner: Bytes32,
//!     #[pso(body, pos=1)]        attester: Address,
//!     #[pso(body, limbed, pos=5)] base: Uint256,  // limbed → [lo, hi]
//! }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{spanned::Spanned, Data, DeriveInput, Fields, Ident, Type};

#[proc_macro_derive(Entity, attributes(pso))]
pub fn derive_entity(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    expand(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[derive(Default)]
struct Roles {
    id_seed: bool,
    id_body: bool,
    body: bool,
    owner: bool,
    skip: bool,
}

struct FieldCfg {
    roles: Roles,
    pos: Option<u64>,
    /// `#[pso(limbed)]`: a scalar field folds through `FieldEncode` to the
    /// multiple elements its type needs, instead of the single-element default.
    limbed: bool,
}

fn parse_field_cfg(field: &syn::Field) -> syn::Result<FieldCfg> {
    let mut roles = Roles::default();
    let mut pos = None;
    let mut limbed = false;
    let mut saw_pso = false;
    for attr in &field.attrs {
        if !attr.path().is_ident("pso") {
            continue;
        }
        saw_pso = true;
        attr.parse_nested_meta(|meta| {
            let id = meta
                .path
                .get_ident()
                .ok_or_else(|| meta.error("expected a bare role ident"))?
                .to_string();
            match id.as_str() {
                "id_seed" => roles.id_seed = true,
                "id_body" => roles.id_body = true,
                "body" => roles.body = true,
                "owner" => roles.owner = true,
                "skip" => roles.skip = true,
                "limbed" => limbed = true,
                "pos" | "position" => {
                    let lit: syn::LitInt = meta.value()?.parse()?;
                    pos = Some(lit.base10_parse()?);
                }
                other => {
                    return Err(meta.error(format!(
                        "unknown pso key `{other}` (expected id_seed, id_body, body, owner, skip, limbed, or pos = N)"
                    )))
                }
            }
            Ok(())
        })?;
    }
    if !saw_pso {
        return Err(syn::Error::new(
            field.span(),
            "every field must carry a `#[pso(...)]` role (use `#[pso(skip)]` to exclude it from the hash)",
        ));
    }
    Ok(FieldCfg { roles, pos, limbed })
}

/// Resolve a fold group's order: declaration order when no field sets
/// `pos`, otherwise sorted by `pos` (all-or-nothing, positions unique).
/// Each entry carries an opaque payload (the field's type + its `limbed`
/// flag) so emission can pick the right per-field encoding.
fn order_group<P>(
    fields: Vec<(Option<u64>, Ident, P)>,
    what: &str,
) -> syn::Result<Vec<(Ident, P)>> {
    if fields.iter().all(|(p, _, _)| p.is_none()) {
        return Ok(fields.into_iter().map(|(_, i, p)| (i, p)).collect());
    }
    if let Some((_, ident, _)) = fields.iter().find(|(p, _, _)| p.is_none()) {
        return Err(syn::Error::new(
            ident.span(),
            format!("`{ident}` has no `pos`, but another `{what}` field does; set `pos` on every `{what}` field or none"),
        ));
    }
    let mut fields = fields;
    fields.sort_by_key(|(p, _, _)| p.unwrap());
    for w in fields.windows(2) {
        if w[0].0 == w[1].0 {
            return Err(syn::Error::new(
                w[1].1.span(),
                format!(
                    "duplicate `pos = {}` among `{what}` fields",
                    w[1].0.unwrap()
                ),
            ));
        }
    }
    Ok(fields.into_iter().map(|(_, i, p)| (i, p)).collect())
}

/// If `ty` is `Vec<T>` (or `std::vec::Vec<T>`), return its element type `T`.
/// A `Vec` body/id_body field is hashed as a canonical *set* (length-prefixed,
/// strictly ascending) via [`pso_protocol::codec::SortedSet`] rather
/// than the ambiguous bare-slice concatenation.
fn vec_elem(ty: &Type) -> Option<Type> {
    let Type::Path(tp) = ty else { return None };
    let seg = tp.path.segments.last()?;
    if seg.ident != "Vec" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    args.args.iter().find_map(|a| match a {
        syn::GenericArgument::Type(t) => Some(t.clone()),
        _ => None,
    })
}

/// Emit the per-field encode call for a body / id_body field:
/// - `Vec<T>`              → the canonical sorted-set `FieldEncode` (via `SortedSet`);
/// - scalar + `limbed`     → the variable-width `FieldEncode` (its type's limbs);
/// - scalar (default)      → a single `FieldElement` (exactly one element).
fn emit_encode(ident: &Ident, ty: &Type, limbed: bool) -> proc_macro2::TokenStream {
    if vec_elem(ty).is_some() {
        quote! { ::pso_protocol::FieldEncode::<S::Field>::encode(&::pso_protocol::codec::SortedSet(&self.#ident), out)?; }
    } else if limbed {
        quote! { ::pso_protocol::FieldEncode::<S::Field>::encode(&self.#ident, out)?; }
    } else {
        quote! { out.push(::pso_protocol::FieldElement::<S::Field>::to_field(&self.#ident)?); }
    }
}

fn expand(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            input.generics.span(),
            "#[derive(Entity)] requires a struct with no generic parameters; the suite `S` is introduced by the generated impl",
        ));
    }
    let name = &input.ident;
    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(n) => &n.named,
            _ => {
                return Err(syn::Error::new(
                    input.span(),
                    "#[derive(Entity)] requires a struct with named fields",
                ))
            }
        },
        _ => {
            return Err(syn::Error::new(
                input.span(),
                "#[derive(Entity)] can only be derived for structs",
            ))
        }
    };

    let mut seed: Option<(Ident, Type)> = None;
    let mut owner: Option<(Ident, Type)> = None;
    // Payload per body / id_body field: its type + whether it is `limbed`.
    let mut id_body: Vec<(Option<u64>, Ident, (Type, bool))> = Vec::new();
    let mut body: Vec<(Option<u64>, Ident, (Type, bool))> = Vec::new();

    for f in fields {
        let ident = f.ident.clone().unwrap();
        let ty = f.ty.clone();
        let FieldCfg { roles, pos, limbed } = parse_field_cfg(f)?;
        if roles.skip {
            continue;
        }
        if limbed && vec_elem(&ty).is_some() {
            return Err(syn::Error::new(
                ident.span(),
                "`limbed` applies to scalar fields; a `Vec<T>` field is a set of single-element items",
            ));
        }
        if roles.id_seed {
            if seed.is_some() {
                return Err(syn::Error::new(ident.span(), "duplicate `#[pso(id_seed)]`"));
            }
            seed = Some((ident.clone(), ty.clone()));
        }
        if roles.owner {
            if owner.is_some() {
                return Err(syn::Error::new(ident.span(), "duplicate `#[pso(owner)]`"));
            }
            owner = Some((ident.clone(), ty.clone()));
        }
        if roles.id_body {
            id_body.push((pos, ident.clone(), (ty.clone(), limbed)));
        }
        if roles.body {
            body.push((pos, ident.clone(), (ty.clone(), limbed)));
        }
    }

    let (seed_ident, seed_ty) = seed.ok_or_else(|| {
        syn::Error::new(
            name.span(),
            "an entity needs exactly one `#[pso(id_seed)]` field",
        )
    })?;
    let id_body = order_group(id_body, "id_body")?;
    let body = order_group(body, "body")?;

    // Dedup where-clause predicates by their textual form.
    let mut seen = std::collections::HashSet::new();
    let mut predicates: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut push_pred = |ty: &Type, single: bool| {
        let key = (single, quote!(#ty).to_string());
        if seen.insert(key) {
            predicates.push(if single {
                quote!(#ty: ::pso_protocol::FieldElement<S::Field>)
            } else {
                quote!(#ty: ::pso_protocol::FieldEncode<S::Field>)
            });
        }
    };
    // The id seed is a single element.
    push_pred(&seed_ty, true);
    // Each body / id_body field's bound mirrors its encoding: a `Vec<T>` folds
    // as a sorted set, so its *element* must be a single `FieldElement`; a
    // `limbed` scalar folds through `FieldEncode` (its type's natural width);
    // a plain scalar is a single `FieldElement` (the default). (The owner type
    // is also bound by the `Owned` impl below.)
    for (_, (ty, limbed)) in id_body.iter().chain(body.iter()) {
        match vec_elem(ty) {
            Some(elem) => push_pred(&elem, true),
            None => push_pred(ty, !*limbed),
        }
    }

    let id_body_encode = id_body.iter().map(|(i, (t, l))| emit_encode(i, t, *l));
    let body_encode = body.iter().map(|(i, (t, l))| emit_encode(i, t, *l));

    let entity_impl = quote! {
        impl<S: ::pso_protocol::Suite> ::pso_protocol::protocol::entity::Entity<S> for #name
        where #(#predicates),*
        {
            fn id_seed(&self) -> ::core::result::Result<S::Field, ::pso_protocol::error::Error> {
                <#seed_ty as ::pso_protocol::FieldElement<S::Field>>::to_field(&self.#seed_ident)
            }
            fn encode_id_body(&self, out: &mut ::std::vec::Vec<S::Field>)
                -> ::core::result::Result<(), ::pso_protocol::error::Error>
            {
                #( #id_body_encode )*
                ::core::result::Result::Ok(())
            }
            fn encode_body(&self, out: &mut ::std::vec::Vec<S::Field>)
                -> ::core::result::Result<(), ::pso_protocol::error::Error>
            {
                #( #body_encode )*
                ::core::result::Result::Ok(())
            }
        }
    };

    let owned_impl = owner.map(|(owner_ident, owner_ty)| {
        quote! {
            impl<S: ::pso_protocol::Suite> ::pso_protocol::protocol::entity::Owned<S> for #name
            where #owner_ty: ::pso_protocol::FieldElement<S::Field>
            {
                fn owner(&self) -> ::core::result::Result<S::Field, ::pso_protocol::error::Error> {
                    <#owner_ty as ::pso_protocol::FieldElement<S::Field>>::to_field(&self.#owner_ident)
                }
            }
        }
    });

    Ok(quote! {
        #entity_impl
        #owned_impl
    })
}
