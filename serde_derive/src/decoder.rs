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

fn gen_read_bytes_inline(size: usize) -> proc_macro2::TokenStream {
    quote! {
        if *offset + #size > buf.len() {
            // return Err(format!(
            //     "decode error: out of bounds, need {} bytes, remain {}",
            //     #size,
            //     buf.len() - *offset
            // ));
            panic!();
        }
        let bytes = &buf[*offset..*offset + #size];
        *offset += #size;
    }
}

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
                        break;
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

fn gen_decode_for_normal(
    field: &syn::Field,
    order: ByteOrder,
    field_map: &HashMap<syn::Ident, (syn::Type, FieldAttrs)>,
) -> proc_macro2::TokenStream {
    let name = field.ident.as_ref().unwrap();
    let ty = &field.ty;

    match ty {
        Type::Array(arr) => {
            let len = match &arr.len {
                syn::Expr::Lit(lit) => {
                    if let syn::Lit::Int(lit) = &lit.lit {
                        lit.base10_parse::<usize>().unwrap()
                    } else {
                        0
                    }
                }
                _ => 0,
            };

            quote! {
                let mut #name = [0u8; #len];
                #name.copy_from_slice(&buf[offset..offset + #len]);
                offset += #len;
            }
        }

        Type::Reference(type_ref) => {
            if let Type::Slice(_) = &*type_ref.elem {
                // dynamic_len_handle()
                quote! {}
            } else {
                quote! {}
            }
        }
        Type::Path(_) => gen_decode_for_normal_path(name, ty, order, field_map),
        _ => quote! {},
    }
}

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
                decode_std_data(name, ty, field_map)
            } else {
                quote! { let #name = #ty::decode(&buf, offset)?; }
            }
        }
        _ => quote! {},
    }
}

fn decode_dynamic_list_data(inner_ty: &Type) -> proc_macro2::TokenStream {
    if is_primitive_type(inner_ty) {
        quote! {}
    } else if is_std_type(inner_ty) {
        quote! {}
    } else {
        quote! {
            for v in dynamic_list.iter() {
                v.encode(buf);
            }
        }
    }
}

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
                        #handle;
                        let #name = bytes[0] == 1;
                    }
                }
                "u8" => {
                    let handle = gen_read_bytes_inline(1);
                    quote! {
                        #handle;
                        let #name = bytes[0];
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
                "u32" => {
                    let handle = gen_read_bytes_inline(4);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle;
                            let #name = u32::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            handle;
                            let #name = u32::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "u64" => {
                    let handle = gen_read_bytes_inline(8);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle;
                            let #name = u64::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle;
                            let #name = u64::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "i8" => quote! {
                    let bytes = read_bytes_checked!(buf, offset, 1);
                    let #name = bytes[0] as i8;
                },
                "i16" => {
                    let handle = gen_read_bytes_inline(2);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle;
                            let #name = i16::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle;
                            let #name = i16::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "i32" => {
                    let handle = gen_read_bytes_inline(4);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle;
                            let #name = i32::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle;
                            let #name = i32::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "i64" => {
                    let handle = gen_read_bytes_inline(8);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle;
                            let #name = i64::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle;
                            let #name = i64::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "f32" => {
                    let handle = gen_read_bytes_inline(4);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle;
                            let #name = f32::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle;
                            let #name = f32::from_le_bytes(bytes.try_into().unwrap());
                        },
                    }
                }
                "f64" => {
                    let handle = gen_read_bytes_inline(8);
                    match byte_order {
                        ByteOrder::BE => quote! {
                            #handle;
                            let #name = f64::from_be_bytes(bytes.try_into().unwrap());
                        },
                        ByteOrder::LE => quote! {
                            #handle;
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

fn decode_std_data(
    name: &syn::Ident,
    ty: &Type,
    field_map: &HashMap<syn::Ident, (syn::Type, FieldAttrs)>,
) -> proc_macro2::TokenStream {
    match ty {
        Type::Path(tp) => {
            let ident = tp.path.segments.last().unwrap().ident.to_string();
            match ident.as_str() {
                "String" => {
                    let filed_attrs = &field_map.get(&name).unwrap().1;
                    let str_delimiter = filed_attrs
                        .str_delimiter
                        .clone()
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

                        let Some(end) = end else {
                            panic!("decode error: String without delimiter");
                        };
                        let #name = String::from_utf8_lossy(&buf[start..end-1]).to_string();
                    }
                }
                "Vec" => {
                    let filed_attrs = &field_map.get(&name).unwrap().1;
                    let len_literal = filed_attrs.len.clone();
                    let len_by_field = filed_attrs.len_by_field.clone();

                    match (len_literal, len_by_field) {
                        (Some(lit), _) => quote! {
                            let slice_len = #lit;
                            if *offset + slice_len > buf.len() {
                                panic!("decode error: field `{}` length out of range", stringify!(#name));
                            }
                            let #name = buf[*offset..*offset + slice_len].to_vec();
                            *offset += slice_len;
                        },
                        (_, Some(field_ident)) => {
                            let field_ty =
                                field_map.get(&field_ident).expect("Unkown field").0.clone();

                            quote! {
                                let slice_len: usize = (#field_ident as usize);
                                if *offset + slice_len > buf.len() {
                                    panic!("decode error: field `{}` length out of range", stringify!(#name));
                                }
                                let #name = buf[*offset..*offset + slice_len].to_vec();
                                *offset += slice_len;

                                let #field_ident: #field_ty = slice_len.try_into().unwrap();
                            }
                        }
                        _ => panic!("Slice Or Vec Need len(..) or len_by_field(..)"),
                    }
                }
                _ => quote! {},
            }
        }
        _ => quote! {},
    }
}
