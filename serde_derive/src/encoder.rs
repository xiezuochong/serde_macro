use std::collections::HashMap;

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Type, parse_macro_input};

use crate::{
    ByteOrder,
    bitfield::{BitAttr, BitFieldAccum},
    is_primitive_type, is_primitive_type_str, is_std_type, is_std_type_str, is_struct_type,
};

pub fn encode_input(input: TokenStream) -> TokenStream {
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
                "BE" => byte_order = ByteOrder::BE,
                "LE" => byte_order = ByteOrder::LE,
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

pub fn gen_bitfield_encode(acc: &BitFieldAccum, byte_order: ByteOrder) -> proc_macro2::TokenStream {
    let mut stmts = Vec::new();

    let byte_len = (acc.total_bits + 7) / 8;

    stmts.push(quote! {
        let mut byte_array = [0u8; #byte_len];
        let mut bits: u64 = 0;
        let mut bit_shift: u32 = 0;
    });

    let mut is_first = true;

    for (name, _, bit_len) in &acc.fields {
        if is_first {
            is_first = false
        }
        stmts.push(quote! {
            let mask: u64 = ::serde_lib::mask_for_bits(#bit_len as u32);
            let value = (self.#name as u64) & mask;

            bits |= value << bit_shift;
            bit_shift += #bit_len as u32;
        });
    }

    match byte_order {
        ByteOrder::LE => {
            stmts.push(quote! {
                for i in 0..#byte_len {
                    byte_array[i] = ((bits >> (i * 8)) & 0xFF) as u8;
                }
                buf.extend_from_slice(&byte_array);
            });
        }
        ByteOrder::BE => {
            stmts.push(quote! {
                for i in 0..#byte_len {
                    byte_array[#byte_len - 1 - i] = ((bits >> (i * 8)) & 0xFF) as u8;
                }
                buf.extend_from_slice(&byte_array);
            });
        }
    }

    quote! { #(#stmts)* }
}

fn gen_encode_for_normal(
    name: &syn::Ident,
    ty: &Type,
    byte_order: ByteOrder,
) -> proc_macro2::TokenStream {
    match ty {
        Type::Array(_) => quote! { buf.extend_from_slice(&self.#name); },
        Type::Reference(type_ref) => match &*type_ref.elem {
            Type::Slice(ts) => {
                let elem_ty = &*ts.elem;
                if is_struct_type(elem_ty) {
                    quote! {
                        for x in self.#name {
                            x.encode(buf);
                        }
                    }
                } else {
                    quote! { buf.extend_from_slice(&self.#name); }
                }
            }
            Type::Path(_) => encode_for_normal_path(name, &type_ref.elem, byte_order),
            _ => quote! {},
        },
        Type::Path(_) => encode_for_normal_path(name, ty, byte_order),

        _ => quote! {},
    }
}

fn encode_for_normal_path(
    name: &syn::Ident,
    ty: &Type,
    byte_order: ByteOrder,
) -> proc_macro2::TokenStream {
    match ty {
        Type::Path(tp) => {
            let ident = &tp.path.segments.last().unwrap().ident.to_string();
            if is_primitive_type_str(&ident) {
                let handle = encode_primitive_data(ty, byte_order);
                quote! { let v: #ty = self.#name.into(); #handle }
            } else if is_std_type_str(&ident) {
                let handle = encode_std_data(ty, byte_order);
                quote! { let v = &self.#name; #handle }
            } else {
                quote! { self.#name.encode(buf); }
            }
        }
        _ => quote! {},
    }
}

fn encode_dynamic_list_data(inner_ty: &Type, byte_order: ByteOrder) -> proc_macro2::TokenStream {
    if is_primitive_type(inner_ty) {
        let handle = encode_primitive_data(inner_ty, byte_order);
        quote! {
            for &v in dynamic_list.iter() {
                #handle
            }
        }
    } else if is_std_type(inner_ty) {
        let handle = encode_std_data(inner_ty, byte_order);
        quote! {
            for v in dynamic_list.iter() {
                #handle
            }
        }
    } else {
        quote! {
            for v in dynamic_list.iter() {
                v.encode(buf);
            }
        }
    }
}

fn encode_primitive_data(ty: &Type, byte_order: ByteOrder) -> proc_macro2::TokenStream {
    match ty {
        Type::Path(tp) => {
            let ident = tp.path.segments.last().unwrap().ident.to_string();
            match ident.as_str() {
                "bool" => quote! { buf.put_u8(v as u8); },
                "u8" => quote! { buf.put_u8(v); },
                "i8" => quote! { buf.put_i8(v); },
                "u16" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_u16_be(v); },
                    ByteOrder::LE => quote! { buf.put_u16_le(v); },
                },
                "i16" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_i16_be(v); },
                    ByteOrder::LE => quote! { buf.put_i16_le(v); },
                },
                "u32" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_u32_be(v); },
                    ByteOrder::LE => quote! { buf.put_u32_le(v); },
                },
                "i32" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_i32_be(v); },
                    ByteOrder::LE => quote! { buf.put_i32_le(v); },
                },
                "u64" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_u64_be(v); },
                    ByteOrder::LE => quote! { buf.put_u64_le(v); },
                },
                "i64" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_i64_be(v); },
                    ByteOrder::LE => quote! { buf.put_i64_le(v); },
                },
                "f32" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_f32_be(v); },
                    ByteOrder::LE => quote! { buf.put_f32_le(v); },
                },
                "f64" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_f64_be(v); },
                    ByteOrder::LE => quote! { buf.put_f64_le(v); },
                },
                _ => quote! {},
            }
        }
        _ => quote! {},
    }
}

fn encode_std_data(ty: &Type, byte_order: ByteOrder) -> proc_macro2::TokenStream {
    match ty {
        Type::Path(tp) => {
            let ident = tp.path.segments.last().unwrap().ident.to_string();
            match ident.as_str() {
                "String" | "str" => quote! { buf.extend_from_slice(v.as_bytes()); },
                "Vec" => {
                    let seg = tp.path.segments.last().unwrap();
                    // 必须是 Vec<T> 这种带泛型的形式
                    if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                        if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                            let encode_dynamic_list_handle =
                                encode_dynamic_list_data(inner_ty, byte_order);
                            return quote! { let dynamic_list = &v; #encode_dynamic_list_handle };
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
