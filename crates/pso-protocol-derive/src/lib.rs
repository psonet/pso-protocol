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
//! - `#[pso(owner)]`   — marks the stored `derivedOwner`; emits an
//!   `Owned` impl. Must be a `FieldElement`. Combine with `body`.
//! - `#[pso(skip)]`    — explicitly excluded from the hash preimage.
//! - `#[pso(pos = N)]` — explicit fold position within its group (`body`
//!   or `id_body`). When present, that group is sorted by `N` instead of
//!   following declaration order — so a struct mirroring a `sol!` layout
//!   can fold its fields in the protocol's canonical order regardless of
//!   how the fields are declared. `pos` is all-or-nothing per group, and
//!   positions must be unique. (`position` is accepted as an alias.)
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
//!     #[pso(body, pos=5)]        base: Uint256,   // expands to [lo, hi]
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
}

fn parse_field_cfg(field: &syn::Field) -> syn::Result<FieldCfg> {
    let mut roles = Roles::default();
    let mut pos = None;
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
                "pos" | "position" => {
                    let lit: syn::LitInt = meta.value()?.parse()?;
                    pos = Some(lit.base10_parse()?);
                }
                other => {
                    return Err(meta.error(format!(
                        "unknown pso key `{other}` (expected id_seed, id_body, body, owner, skip, or pos = N)"
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
    Ok(FieldCfg { roles, pos })
}

/// Resolve a fold group's order: declaration order when no field sets
/// `pos`, otherwise sorted by `pos` (all-or-nothing, positions unique).
fn order_group(fields: Vec<(Option<u64>, Ident)>, what: &str) -> syn::Result<Vec<Ident>> {
    if fields.iter().all(|(p, _)| p.is_none()) {
        return Ok(fields.into_iter().map(|(_, i)| i).collect());
    }
    if let Some((_, ident)) = fields.iter().find(|(p, _)| p.is_none()) {
        return Err(syn::Error::new(
            ident.span(),
            format!("`{ident}` has no `pos`, but another `{what}` field does; set `pos` on every `{what}` field or none"),
        ));
    }
    let mut fields = fields;
    fields.sort_by_key(|(p, _)| p.unwrap());
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
    Ok(fields.into_iter().map(|(_, i)| i).collect())
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
    let mut id_body: Vec<(Option<u64>, Ident)> = Vec::new();
    let mut body: Vec<(Option<u64>, Ident)> = Vec::new();
    // Type -> bound: `FieldElement` (single element) or `FieldEncode`.
    let mut elem_tys: Vec<Type> = Vec::new();
    let mut encode_tys: Vec<Type> = Vec::new();

    for f in fields {
        let ident = f.ident.clone().unwrap();
        let ty = f.ty.clone();
        let FieldCfg { roles, pos } = parse_field_cfg(f)?;
        if roles.skip {
            continue;
        }
        if roles.id_seed {
            if seed.is_some() {
                return Err(syn::Error::new(ident.span(), "duplicate `#[pso(id_seed)]`"));
            }
            seed = Some((ident.clone(), ty.clone()));
            elem_tys.push(ty.clone());
        }
        if roles.owner {
            if owner.is_some() {
                return Err(syn::Error::new(ident.span(), "duplicate `#[pso(owner)]`"));
            }
            owner = Some((ident.clone(), ty.clone()));
            elem_tys.push(ty.clone());
        }
        if roles.id_body {
            id_body.push((pos, ident.clone()));
            encode_tys.push(ty.clone());
        }
        if roles.body {
            body.push((pos, ident.clone()));
            encode_tys.push(ty.clone());
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
    for ty in &elem_tys {
        push_pred(ty, true);
    }
    for ty in &encode_tys {
        push_pred(ty, false);
    }

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
                #( ::pso_protocol::FieldEncode::<S::Field>::encode(&self.#id_body, out)?; )*
                ::core::result::Result::Ok(())
            }
            fn encode_body(&self, out: &mut ::std::vec::Vec<S::Field>)
                -> ::core::result::Result<(), ::pso_protocol::error::Error>
            {
                #( ::pso_protocol::FieldEncode::<S::Field>::encode(&self.#body, out)?; )*
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
