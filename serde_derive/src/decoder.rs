use std::collections::HashMap;

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Meta, Type, parse_macro_input};

use crate::{
    ByteOrder, MetaListParser,
    bitfield::{BitAttr, BitFieldAccum},
    is_struct_type,
};

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

pub fn gen_bitfield_decode(acc: &BitFieldAccum, byte_order: ByteOrder) -> proc_macro2::TokenStream {
    let mut stmts = Vec::new();

    let byte_len = (acc.total_bits + 7) / 8;

    // --- 字节序专用 decode 模板 ---
    let read_bits = match byte_order {
        ByteOrder::LE => quote! {
            let mut bits: u64 = 0;
            // BE：高字节在前
            for i in 0..#byte_len {
                bits |= (buf[*offset + i] as u64) << ((#byte_len - 1 - i) * 8);
            }
            let mut bit_shift: u32 = 0;
            *offset += #byte_len;
        },
        ByteOrder::BE => quote! {
            let mut bits: u64 = 0;
            // LE：低字节在前
            for i in 0..#byte_len {
                bits |= (buf[*offset + i] as u64) << (i * 8);
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

pub fn gen_decode_for_normal(
    field: &syn::Field,
    order: ByteOrder,
    field_map: &HashMap<syn::Ident, syn::Type>,
) -> proc_macro2::TokenStream {
    let name = field.ident.as_ref().unwrap();
    let ty = &field.ty;

    let dynamic_len_handle = || {
        let mut len_literal = None;
        let mut len_by_field = None;
        for attr in &field.attrs {
            let Some(ident) = attr.path().get_ident() else {
                break;
            };

            match ident.to_string().as_str() {
                "len" => {
                    if let Meta::List(list) = &attr.meta {
                        let lit: syn::LitInt =
                            syn::parse2(list.tokens.clone()).expect("len(...) must be integer");

                        len_literal = Some(
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
                            len_by_field = Some(path.get_ident().unwrap().clone())
                        }
                    }
                }
                _ => (),
            }
        }
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
                let field_ty = field_map.get(&field_ident).expect("Unkown field");

                quote! {
                    let slice_len: usize = (#field_ident as usize);
                    if *offset + slice_len > buf.len() {
                        panic!("decode error: field `{}` length out of range", stringify!(#name));
                    }
                    let #name = buf[*offset..*offset + slice_len].to_vec();
                    *offset += slice_len;

                    // 如果你结构体里的字段类型是 u16，需要赋值给它：
                    let #field_ident: #field_ty = slice_len.try_into().unwrap();
                }
            }
            _ => panic!("Slice Or Vec Need len(..) or len_by_field(..)"),
        }
    };

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
                dynamic_len_handle()
            } else {
                quote! {}
            }
        }

        Type::Path(tp) => {
            let ident = &tp.path.segments.last().unwrap().ident;
            match ident.to_string().as_str() {
                "bool" => quote! {
                    let #name = buf[*offset] == 1;
                    *offset += 1;
                },
                "u8" => quote! {
                    let #name = buf[*offset];
                    *offset += 1;
                },
                "i8" => quote! {
                    let #name = buf[*offset];
                    *offset += 1;
                },
                "u16" => match order {
                    ByteOrder::BE => quote! {
                        let #name = u16::from_be_bytes(buf[*offset..*offset + 2].try_into().unwrap());
                        *offset += 2;
                    },
                    ByteOrder::LE => quote! {
                        let #name = u16::from_le_bytes(buf[*offset..*offset + 2].try_into().unwrap());
                        *offset += 2;
                    },
                },
                "i16" => match order {
                    ByteOrder::BE => quote! {
                        let #name = i16::from_be_bytes(buf[*offset..*offset + 2].try_into().unwrap());
                        *offset += 2;
                    },
                    ByteOrder::LE => quote! {
                        let #name = i16::from_le_bytes(buf[*offset..*offset + 2].try_into().unwrap());
                        *offset += 2;
                    },
                },
                "u32" => match order {
                    ByteOrder::BE => quote! {
                        let #name = u32::from_be_bytes(buf[*offset..*offset + 4].try_into().unwrap());
                        *offset += 4;
                    },
                    ByteOrder::LE => quote! {
                        let #name = u32::from_le_bytes(buf[*offset..*offset + 4].try_into().unwrap());
                        *offset += 4;
                    },
                },
                "i32" => match order {
                    ByteOrder::BE => quote! {
                        let #name = i32::from_be_bytes(buf[*offset..*offset + 4].try_into().unwrap());
                        *offset += 4;
                    },
                    ByteOrder::LE => quote! {
                        let #name = i32::from_le_bytes(buf[*offset..*offset + 4].try_into().unwrap());
                        *offset += 4;
                    },
                },
                "f32" => match order {
                    ByteOrder::BE => quote! {
                        let #name = f32::from_be_bytes(buf[*offset..*offset + 4].try_into().unwrap());
                        *offset += 4;
                    },
                    ByteOrder::LE => quote! {
                        let #name = f32::from_le_bytes(buf[*offset..*offset + 4].try_into().unwrap());
                        *offset += 4;
                    },
                },
                "u64" => match order {
                    ByteOrder::BE => quote! {
                        let #name = u64::from_be_bytes(buf[*offset..*offset + 8].try_into().unwrap());
                        *offset += 8;
                    },
                    ByteOrder::LE => quote! {
                        let #name = f32::from_le_bytes(buf[*offset..*offset + 8].try_into().unwrap());
                        *offset += 4;
                    },
                },
                "i64" => match order {
                    ByteOrder::BE => quote! {
                        let #name = i32::from_be_bytes(buf[*offset..*offset + 8].try_into().unwrap());
                        *offset += 8;
                    },
                    ByteOrder::LE => quote! {
                        let #name = 8::from_le_bytes(buf[*offset..*offset + 8].try_into().unwrap());
                        *offset += 8;
                    },
                },
                "f64" => match order {
                    ByteOrder::BE => quote! {
                        let #name = f64::from_be_bytes(buf[*offset..*offset + 8].try_into().unwrap());
                        *offset += 8;
                    },
                    ByteOrder::LE => quote! {
                        let #name = f64::from_le_bytes(buf[*offset..*offset + 8].try_into().unwrap());
                        *offset += 8;
                    },
                },
                "Vec" => dynamic_len_handle(),
                _ => quote! {},
            }
        }

        _ => quote! {},
    }
}
