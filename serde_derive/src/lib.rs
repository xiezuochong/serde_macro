extern crate proc_macro;

mod bitfield;
mod normal;

use std::{collections::HashMap, str::FromStr};

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Data, DeriveInput, Fields, Meta, Result, Token, Type,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
};

use bitfield::{BitAttr, BitFieldAccum, gen_bitfield_decode, gen_bitfield_encode};
use normal::{gen_decode_for_normal, gen_encode_for_normal};

struct MetaListParser(Punctuated<Meta, Token![,]>);

impl Parse for MetaListParser {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(MetaListParser(Punctuated::parse_terminated(input)?))
    }
}

fn parse_int<T: std::str::FromStr>(expr: syn::Expr) -> Option<T>
where
    <T as FromStr>::Err: std::fmt::Display,
{
    if let syn::Expr::Lit(expr_lit) = expr {
        if let syn::Lit::Int(lit) = expr_lit.lit {
            return lit.base10_parse::<T>().ok();
        }
    }
    None
}

fn is_struct_type(ty: &Type) -> bool {
    match ty {
        // 不是结构体
        Type::Array(_) => return false,
        Type::Reference(type_ref) => {
            if let Type::Slice(_) = &*type_ref.elem {
                return false;
            }
        }
        _ => {}
    }

    if let Type::Path(tp) = ty {
        let seg = tp.path.segments.last().unwrap();

        // 排除泛型（如 Vec<u8>）
        if !seg.arguments.is_empty() {
            return false;
        }

        let ident = seg.ident.to_string();

        match ident.as_str() {
            // primitive
            "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "bool" | "String" => {
                false
            }
            _ => true, // 其余全部是结构体
        }
    } else {
        false
    }
}

#[derive(Debug, Clone, Copy)]
enum ByteOrder {
    LE,
    BE,
}

#[proc_macro_derive(Encoder, attributes(ByteOrder, bitfield))]
pub fn encoder_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let mut field_map = HashMap::new();

    let mut encode_stmts = Vec::new();

    let mut acc = BitFieldAccum::new();
    let mut byte_order = ByteOrder::LE;

    for attr in &input.attrs {
        if attr.path().is_ident("ByteOrder") {
            let meta = attr.parse_args::<syn::Ident>().unwrap();
            let s = meta.to_string().to_uppercase();

            match s.as_str() {
                "LE" => byte_order = ByteOrder::LE,
                "BE" => byte_order = ByteOrder::BE,
                _ => panic!("Invalid byte order: {}", s),
            }
        }
    }

    if let Data::Struct(data) = &input.data {
        if let Fields::Named(fields) = &data.fields {
            for field in &fields.named {
                let name = field.ident.clone().unwrap();
                let ty = &field.ty;

                field_map.insert(name.clone(), ty.clone());

                if is_struct_type(ty) {
                    if acc.is_active() {
                        panic!("Missing end in bitfield sequence");
                    }
                    encode_stmts.push(quote! {
                        self.#name.encode(buf);
                    });
                } else {
                    if let Some(attr) = BitAttr::from_field(&field) {
                        // bitfield 字段
                        acc.push(name.clone(), ty.clone(), attr.bit_len);

                        if attr.bit_end {
                            encode_stmts.push(gen_bitfield_encode(&acc, byte_order));
                            acc.clear();
                        }
                    } else {
                        if acc.is_active() {
                            panic!("Missing end in bitfield sequence");
                        }
                        encode_stmts.push(gen_encode_for_normal(&name, ty, byte_order));
                    }
                }
            }
        }
    }

    if acc.is_active() {
        panic!("Bitfield block started but no end found");
    }

    let generics = &input.generics;

    let output = quote! {
        impl #generics ::serde_lib::Encode for #struct_name #generics {
            fn encode(&self, buf: &mut BytesMut) {
                #(#encode_stmts)*
            }
        }
    };

    output.into()
}


#[proc_macro_derive(Decoder, attributes(ByteOrder, bitfield, len_by_field, len))]
pub fn decoder_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let mut field_map = HashMap::new();

    let mut decode_stmts = Vec::new();

    let mut acc = BitFieldAccum::new();
    let mut field_inits = Vec::new();
    let mut byte_order = ByteOrder::LE;

    for attr in &input.attrs {
        if attr.path().is_ident("ByteOrder") {
            let meta = attr.parse_args::<syn::Ident>().unwrap();
            let s = meta.to_string().to_uppercase();

            match s.as_str() {
                "LE" => byte_order = ByteOrder::LE,
                "BE" => byte_order = ByteOrder::BE,
                _ => panic!("Invalid byte order: {}", s),
            }
        }
    }

    if let Data::Struct(data) = &input.data {
        if let Fields::Named(fields) = &data.fields {
            for field in &fields.named {
                let name = field.ident.clone().unwrap();
                let ty = &field.ty;

                field_map.insert(name.clone(), ty.clone());

                if is_struct_type(ty) {
                    if acc.is_active() {
                        panic!("Missing end in bitfield sequence");
                    }
                    decode_stmts.push(quote! {
                        let #name = #ty::decode(&buf, offset)?;
                    });
                    field_inits.push(quote! { #name });
                } else {
                    if let Some(attr) = BitAttr::from_field(&field) {
                        // bitfield 字段
                        acc.push(name.clone(), ty.clone(), attr.bit_len);

                        if attr.bit_end {
                            decode_stmts.push(gen_bitfield_decode(&acc, byte_order));
                            for (f, _, _) in &acc.fields {
                                field_inits.push(quote! { #f });
                            }
                            acc.clear();
                        }
                    } else {
                        if acc.is_active() {
                            panic!("Missing end in bitfield sequence");
                        }
                        decode_stmts.push(gen_decode_for_normal(&field, byte_order, &field_map));
                        field_inits.push(quote! { #name });
                    }
                }
            }
        }
    }

    if acc.is_active() {
        panic!("Bitfield block started but no end found");
    }

    let generics = &input.generics;

    let output = quote! {
        impl #generics ::serde_lib::Decode for #struct_name #generics {
            fn decode(buf: &[u8], offset: &mut usize) -> ::std::result::Result<Self, ::serde_lib::byte::Error> {
                use ::bytes::Buf;

                #(#decode_stmts)*

                Ok(Self {
                    #(#field_inits),*
                })
            }
        }
    };

    output.into()
}
