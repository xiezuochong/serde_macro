use std::collections::HashMap;

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, Meta, Type, parse_macro_input};

use crate::{
    ByteOrder, MetaListParser,
    bitfield::{BitAttr, BitFieldAccum},
    is_primitive_type, is_primitive_type_str, is_std_type, is_std_type_str, is_struct_type,
};

#[derive(Default)]
struct FieldAttrs {
    len: Option<usize>,
    len_by_field: Option<Ident>,
    str_delimiter: Option<u8>,
}

impl FieldAttrs {
    fn set_len(&mut self, len: usize) {
        if self.len_by_field.is_some() {
            panic!("confict with len_by_field(..)");
        }
        self.len = Some(len)
    }

    fn set_len_by_field(&mut self, ident: Ident) {
        if self.len.is_some() {
            panic!("confict with len(..)");
        }
        self.len_by_field = Some(ident)
    }

    fn set_str_delimiter(&mut self, delimiter: u8) {
        self.str_delimiter = Some(delimiter)
    }
}

/// Inline read-bytes template (no macro / no fn).
fn gen_read_bytes_inline(size: usize) -> proc_macro2::TokenStream {
    quote! {
        if *offset + #size > buf.len() {
            panic!("decode error: out of bounds, need {} bytes, remain {}", #size, buf.len() - *offset);
        }
        let bytes = &buf[*offset..*offset + #size];
        *offset += #size;
    }
}

/// extract Vec<T> inner type
fn extract_vec_inner_type(ty: &Type) -> Option<&Type> {
    if let Type::Path(tp) = ty {
        let seg = tp.path.segments.last().unwrap();
        if seg.ident == "Vec" {
            if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                    return Some(inner_ty);
                }
            }
        }
    }
    None
}

/// extract array len literal
fn extract_array_len(expr: &syn::Expr) -> usize {
    match expr {
        syn::Expr::Lit(lit) => {
            if let syn::Lit::Int(i) = &lit.lit {
                i.base10_parse::<usize>().unwrap()
            } else {
                0
            }
        }
        _ => 0,
    }
}

/// ---------- high level decode_input (same structure as yours) ----------
pub fn decode_input(input: TokenStream) -> TokenStream {
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

                let mut field_attrs = FieldAttrs::default();

                for attr in &field.attrs {
                    let Some(ident) = attr.path().get_ident() else {
                        continue;
                    };

                    match ident.to_string().as_str() {
                        "len" => {
                            if let Meta::List(list) = &attr.meta {
                                let lit: syn::LitInt = syn::parse2(list.tokens.clone())
                                    .expect("len(...) must be integer");

                                field_attrs.set_len(
                                    lit.base10_parse::<usize>()
                                        .expect("len(...) parse integer failed"),
                                );
                            }
                        }
                        "len_by_field" => {
                            if let Meta::List(list) = &attr.meta {
                                let nested = syn::parse2::<MetaListParser>(list.tokens.clone())
                                    .expect("Invalid len_by_field(...) format")
                                    .0;
                                if let Some(Meta::Path(path)) = nested.first() {
                                    field_attrs.set_len_by_field(path.get_ident().unwrap().clone());
                                }
                            }
                        }
                        "delimiter" => {
                            if let Meta::List(list) = &attr.meta {
                                let lit: syn::LitInt = syn::parse2(list.tokens.clone())
                                    .expect("delimiter(...) must be integer");

                                field_attrs.set_str_delimiter(
                                    lit.base10_parse::<u8>()
                                        .expect("delimiter(...) parse u8 failed"),
                                );
                            }
                        }
                        _ => (),
                    }
                }

                field_map.insert(name.clone(), (ty.clone(), field_attrs));

                if is_struct_type(ty) {
                    if acc.is_active() {
                        panic!("Missing end in bitfield sequence");
                    }
                    decode_stmts.push(quote! {
                        let #name = #ty::decode(buf, offset)?;
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
                        decode_stmts.push(gen_decode_for_normal(field, byte_order, &field_map));
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

/// ---------- bitfield decode (unchanged) ----------
pub fn gen_bitfield_decode(acc: &BitFieldAccum, byte_order: ByteOrder) -> proc_macro2::TokenStream {
    let mut stmts = Vec::new();

    let byte_len = (acc.total_bits + 7) / 8;

    // --- 字节序专用 decode 模板 ---
    let read_bits = match byte_order {
        ByteOrder::BE => quote! {
            let mut bits: u64 = 0;
            // LE：低字节在前
            for i in 0..#byte_len {
                bits |= (buf[*offset + i] as u64) << (i * 8);
            }
            let mut bit_shift: u32 = 0;
            *offset += #byte_len;
        },
        ByteOrder::LE => quote! {
            let mut bits: u64 = 0;
            // BE：高字节在前
            for i in 0..#byte_len {
                bits |= (buf[*offset + i] as u64) << ((#byte_len - 1 - i) * 8);
            }
            let mut bit_shift: u32 = 0;
            *offset += #byte_len;
        },
    };

    stmts.push(read_bits);

    for (name, ty, bit_len) in &acc.fields {
        let stmt = match ty {
            Type::Path(tp) => {
                let ident = &tp.path.segments.last().unwrap().ident;
                match ident.to_string().as_str() {
                    "bool" => quote! {
                        let mask: u64 = ::serde_lib::mask_for_bits(#bit_len as u32);
                        let #name: bool = ((bits >> bit_shift) & mask) != 0;
                        bit_shift += #bit_len as u32;
                    },
                    _ => quote! {
                        let mask: u64 = ::serde_lib::mask_for_bits(#bit_len as u32);
                        let #name: #ty = ((bits >> bit_shift) & mask) as #ty;
                        bit_shift += #bit_len as u32;
                    },
                }
            }
            _ => {
                quote! {}
            }
        };

        stmts.push(stmt);
    }

    quote! { #(#stmts)* }
}

/// ---------- core generation for normal fields ----------
fn gen_decode_for_normal(
    field: &syn::Field,
    order: ByteOrder,
    field_map: &HashMap<syn::Ident, (syn::Type, FieldAttrs)>,
) -> proc_macro2::TokenStream {
    let name = field.ident.as_ref().unwrap();
    let ty = &field.ty;

    match ty {
        Type::Array(arr) => {
            let len = extract_array_len(&arr.len);
            let inner = &*arr.elem;
            gen_decode_array(name, inner, len, order)
        }

        Type::Reference(type_ref) => {
            if let Type::Slice(ts) = &*type_ref.elem {
                // dynamic length slice: must use len or len_by_field from field attrs
                let attrs = &field_map.get(name).unwrap().1;
                gen_decode_dynamic_slice(name, &*ts.elem, attrs, order)
            } else {
                quote! {}
            }
        }
        Type::Path(_) => gen_decode_for_normal_path(name, ty, order, field_map),
        _ => quote! {},
    }
}

/// dispatch for path types (primitive / std / struct)
fn gen_decode_for_normal_path(
    name: &syn::Ident,
    ty: &Type,
    byte_order: ByteOrder,
    field_map: &HashMap<syn::Ident, (syn::Type, FieldAttrs)>,
) -> proc_macro2::TokenStream {
    match &ty {
        Type::Path(tp) => {
            let ident = &tp.path.segments.last().unwrap().ident.to_string();
            if is_primitive_type_str(&ident) {
                decode_primitive_data(name, ty, byte_order)
            } else if is_std_type_str(&ident) {
                decode_std_data(name, ty, field_map, byte_order)
            } else {
                quote! { let #name = #ty::decode(buf, offset)?; }
            }
        }
        _ => quote! {},
    }
}

/// ---------- decode helpers ----------

/// decode primitive into a local `#name` (uses inline read-bytes)
fn decode_primitive_data(
    name: &syn::Ident,
    ty: &Type,
    byte_order: ByteOrder,
) -> proc_macro2::TokenStream {
    match ty {
        Type::Path(tp) => {
            let ident = &tp.path.segments.last().unwrap().ident;

            match ident.to_string().as_str() {
                "bool" => {
                    let handle = gen_read_bytes_inline(1);
                    quote! {
                        #handle
                        let #name = bytes[0] == 1;
                    }
                }
                "u8" => {
                    let handle = gen_read_bytes_inline(1);
                    quote! {
                        #handle
                        let #name = bytes[0];
                    }
                }
                "i8" => {
                    let handle = gen_read_bytes_inline(1);
                    quote! {
                        #handle
                        let #name = bytes[0] as i8;
                    }
                }
                "u16" => {
                    let handle = gen_read_bytes_inline(2);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle
                            let #name = u16::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle
                            let #name = u16::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "i16" => {
                    let handle = gen_read_bytes_inline(2);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle
                            let #name = i16::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle
                            let #name = i16::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "u32" => {
                    let handle = gen_read_bytes_inline(4);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle
                            let #name = u32::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle
                            let #name = u32::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "i32" => {
                    let handle = gen_read_bytes_inline(4);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle
                            let #name = i32::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle
                            let #name = i32::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "f32" => {
                    let handle = gen_read_bytes_inline(4);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle
                            let #name = f32::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle
                            let #name = f32::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "u64" => {
                    let handle = gen_read_bytes_inline(8);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle
                            let #name = u64::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle
                            let #name = u64::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "i64" => {
                    let handle = gen_read_bytes_inline(8);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle
                            let #name = i64::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle
                            let #name = i64::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "f64" => {
                    let handle = gen_read_bytes_inline(8);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle
                            let #name = f64::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle
                            let #name = f64::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                _ => quote! {},
            }
        }

        _ => quote! {},
    }
}

/// decode standard library types (String, Vec<T>)
fn decode_std_data(
    name: &syn::Ident,
    ty: &Type,
    field_map: &HashMap<syn::Ident, (syn::Type, FieldAttrs)>,
    byte_order: ByteOrder,
) -> proc_macro2::TokenStream {
    match ty {
        Type::Path(tp) => {
            let ident = tp.path.segments.last().unwrap().ident.to_string();
            match ident.as_str() {
                "String" => {
                    let filed_attrs = &field_map.get(&name).unwrap().1;
                    let str_delimiter = filed_attrs
                        .str_delimiter
                        .expect("String need delimiter(...)");

                    quote! {
                        let start = *offset;
                        let mut end = None;
                        for i in start..buf.len() {
                            *offset += 1;
                            if buf[i] == #str_delimiter {
                                end = Some(*offset);
                                break;
                            }
                        }

                        let end = match end {
                            Some(v) => v,
                            None => panic!("decode error: String without delimiter"),
                        };
                        let #name = String::from_utf8_lossy(&buf[start..end-1]).to_string();
                    }
                }
                "Vec" => {
                    // find inner type
                    let seg = tp.path.segments.last().unwrap();
                    if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                        if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                            // determine length source
                            let filed_attrs = &field_map.get(&name).unwrap().1;
                            let len_literal = filed_attrs.len;
                            let len_by_field = filed_attrs.len_by_field.clone();

                            let len_tokens = match (len_literal, len_by_field) {
                                (Some(lit), _) => quote! { #lit },
                                (_, Some(ref field_ident)) => quote! { #field_ident as usize },
                                _ => panic!("Slice Or Vec Need len(..) or len_by_field(..)"),
                            };

                            return gen_decode_vec(name, inner_ty, len_tokens, byte_order);
                        }
                    }
                    quote! {}
                }
                _ => quote! {},
            }
        }
        _ => quote! {},
    }
}

/// generate decode for Vec<inner>
fn gen_decode_vec(
    name: &syn::Ident,
    inner_ty: &Type,
    len_tokens: proc_macro2::TokenStream,
    byte_order: ByteOrder,
) -> proc_macro2::TokenStream {
    // fast path Vec<u8>
    if let Type::Path(p) = inner_ty {
        if p.path.is_ident("u8") {
            return quote! {
                let slice_len = #len_tokens;
                if *offset + slice_len > buf.len() {
                    panic!("decode error: field `{}` length out of range", stringify!(#name));
                }
                let #name = buf[*offset..*offset + slice_len].to_vec();
                *offset += slice_len;
            };
        }
    }

    // primitive numeric inner types
    if is_primitive_type(inner_ty) {
        let elem_size = match inner_ty {
            Type::Path(tp) => {
                let n = tp.path.segments.last().unwrap().ident.to_string();
                match n.as_str() {
                    "u16" | "i16" => 2usize,
                    "u32" | "i32" | "f32" => 4usize,
                    "u64" | "i64" | "f64" => 8usize,
                    "u8" => 1usize,
                    _ => 0usize,
                }
            }
            _ => 0usize,
        };

        if elem_size == 0 {
            // fallback: try element decode loop
            let decode_elem =
                decode_primitive_data(&quote::format_ident!("tmp"), inner_ty, byte_order);
            return quote! {
                let slice_len = #len_tokens;
                let mut #name = Vec::new();
                let end = *offset + slice_len;
                while *offset < end {
                    #decode_elem
                    #name.push(tmp);
                }
            };
        }

        let decode_elem = decode_primitive_data(&quote::format_ident!("tmp"), inner_ty, byte_order);
        return quote! {
            let slice_len = #len_tokens;
            if slice_len % #elem_size != 0 {
                panic!("decode error: slice length not multiple of element size");
            }
            let item_count = slice_len / #elem_size;
            let mut #name = Vec::with_capacity(item_count);
            for _ in 0..item_count {
                #decode_elem
                #name.push(tmp);
            }
        };
    }

    // struct or complex types: iterative decode until consumed
    quote! {
        let slice_len = #len_tokens;
        let mut #name = Vec::new();
        let end = *offset + slice_len;
        while *offset < end {
            #name.push(<#inner_ty>::decode(buf, offset)?);
        }
    }
}

/// generate decode for [T; N]
fn gen_decode_array(
    name: &syn::Ident,
    inner_ty: &Type,
    len: usize,
    byte_order: ByteOrder,
) -> proc_macro2::TokenStream {
    // fast path for [u8; N]
    if let Type::Path(p) = inner_ty {
        if p.path.is_ident("u8") {
            return quote! {
                let mut #name = [0u8; #len];
                #name.copy_from_slice(&buf[*offset..*offset + #len]);
                *offset += #len;
            };
        }
    }

    // otherwise decode per element
    if is_primitive_type(inner_ty) {
        let elem_size = match inner_ty {
            Type::Path(tp) => {
                let n = tp.path.segments.last().unwrap().ident.to_string();
                match n.as_str() {
                    "u16" | "i16" => 2usize,
                    "u32" | "i32" | "f32" => 4usize,
                    "u64" | "i64" | "f64" => 8usize,
                    "u8" => 1usize,
                    _ => 0usize,
                }
            }
            _ => 0usize,
        };

        let decode_elem = decode_primitive_data(&quote::format_ident!("tmp"), inner_ty, byte_order);

        // create default array (requires element default) -- we fallback to using Vec then copy if necessary
        return quote! {
            let mut vec_tmp = Vec::with_capacity(#len);
            for _ in 0..#len {
                #decode_elem
                vec_tmp.push(tmp);
            }
            // convert vec_tmp into array by trying into
            let mut #name = [Default::default(); #len];
            for i in 0..#len {
                #name[i] = vec_tmp[i].clone();
            }
        };
    }

    // generic T: call decode for each element
    quote! {
        let mut #name = [Default::default(); #len];
        for i in 0..#len {
            #name[i] = <#inner_ty>::decode(buf, offset)?;
        }
    }
}

/// decode dynamic slice (&[T]) when T is known; uses field attrs for len/len_by_field
fn gen_decode_dynamic_slice(
    name: &syn::Ident,
    inner: &Type,
    attrs: &FieldAttrs,
    byte_order: ByteOrder,
) -> proc_macro2::TokenStream {
    let len_tokens = match (attrs.len, attrs.len_by_field.clone()) {
        (Some(l), _) => quote! { #l },
        (_, Some(ref field_ident)) => quote! { #field_ident as usize },
        _ => panic!("Slice Or Vec Need len(..) or len_by_field(..)"),
    };

    // reuse gen_decode_vec logic (slice and Vec decode similar)
    gen_decode_vec(name, inner, len_tokens, byte_order)
}
