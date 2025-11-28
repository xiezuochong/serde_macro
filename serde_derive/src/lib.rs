extern crate proc_macro;

mod bitfield;
mod decoder;
mod encoder;

use std::str::FromStr;

use proc_macro::TokenStream;
use syn::{
    Meta, Result, Token, Type,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

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

fn is_primitive_type_str(ty_str: &str) -> bool {
    matches!(
        ty_str,
        "bool" | "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "f32" | "f64"
    )
}

fn is_std_type_str(ty_str: &str) -> bool {
    matches!(ty_str, "String" | "Vec" | "str")
}

fn is_primitive_type(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => {
            let ident = &tp.path.segments.last().unwrap().ident.to_string();
            is_primitive_type_str(ident.as_str())
        }
        _ => false,
    }
}

fn is_std_type(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => {
            let ident = &tp.path.segments.last().unwrap().ident.to_string();
            is_std_type_str(ident.as_str())
        }
        _ => false,
    }
}

fn is_struct_type(ty: &Type) -> bool {
    match ty {
        // 不是结构体
        Type::Array(_) => return false,
        Type::Reference(type_ref) => {
            let ty = &*type_ref.elem;
            is_struct_type(ty)
        }
        Type::Path(tp) => {
            let seg = tp.path.segments.last().unwrap();
            // 排除泛型（如 Vec<u8>）
            if !seg.arguments.is_empty() {
                return false;
            }
            let ident = seg.ident.to_string();

            return !(is_primitive_type_str(&ident) || is_std_type_str(&ident));
        }
        _ => true,
    }
}

#[derive(Debug, Clone, Copy)]
enum ByteOrder {
    LE,
    BE,
}

#[proc_macro_derive(Encoder, attributes(ByteOrder, bitfield))]
pub fn encoder_derive(input: TokenStream) -> TokenStream {
    encoder::encode_input(input)
}

#[proc_macro_derive(Decoder, attributes(ByteOrder, bitfield, len_by_field, len))]
pub fn decoder_derive(input: TokenStream) -> TokenStream {
    decoder::decode_input(input)
}
