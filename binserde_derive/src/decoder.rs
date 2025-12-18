use proc_macro::TokenStream;
use quote::quote;

use crate::*;

pub fn decode_input(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    match &input.data {
        syn::Data::Struct(_) => {
            let struct_name = &input.ident;
            let generics = &input.generics;

            let struct_info = Arc::new(StructInfo::parse(&input));
            let _ = STRUCT_MAP
                .lock()
                .unwrap()
                .insert(struct_name.to_string(), struct_info.clone());

            let (stmts_be, field_inits_be) =
                decode_struct(&input, ByteOrder::BE, &struct_info);
            let (stmts_le, field_inits_le) =
                decode_struct(&input, ByteOrder::LE, &struct_info);
            quote! {
                impl #generics ::binserde::Decode for #struct_name #generics {
                    fn decode_be(buf: &[u8], offset: &mut usize) -> ::std::result::Result<Self, ()> {
                        use ::bytes::Buf;

                        #(#stmts_be)*

                        Ok(Self {
                            #(#field_inits_be),*
                        })
                    }

                    fn decode_le(buf: &[u8], offset: &mut usize) -> ::std::result::Result<Self, ()> {
                        use ::bytes::Buf;

                        #(#stmts_le)*

                        Ok(Self {
                            #(#field_inits_le),*
                        })
                    }
                }
            }
            .into()
        }
        syn::Data::Enum(_) => {
            let enum_name = &input.ident;
            let enum_info = Arc::new(EnumInfo::parse(&input));
            let _ = ENUM_MAP
                .lock()
                .unwrap()
                .insert(enum_name.to_string(), enum_info.clone());

            let stmts_be =
                decode_enum(&input, ByteOrder::BE, &enum_info);
            let stmts_le =
                decode_enum(&input, ByteOrder::LE, &enum_info);

            let generics = &input.generics;
            quote! {
                impl #generics ::binserde::Decode for #enum_name #generics {
                    fn decode_be(buf: &[u8], offset: &mut usize) -> ::std::result::Result<Self, ()> {
                        use ::bytes::Buf;
        
                        #(#stmts_be)*
        
                        // 最终返回枚举值 v
                        Ok(v)
                    }

                    fn decode_le(buf: &[u8], offset: &mut usize) -> ::std::result::Result<Self, ()> {
                        use ::bytes::Buf;
        
                        #(#stmts_le)*
        
                        // 最终返回枚举值 v
                        Ok(v)
                    }
                }
            }
        },
        syn::Data::Union(_) => todo!(),
    }
    .into()
}

fn decode_struct(
    input: &syn::DeriveInput,
    byte_order: ByteOrder,
    struct_info: &StructInfo,
) -> (Vec<proc_macro2::TokenStream>, Vec<proc_macro2::TokenStream>) {
    let mut decode_stmts: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut field_inits: Vec<proc_macro2::TokenStream> = Vec::new();

    let syn::Data::Struct(data_struct) = &input.data else {
        return (decode_stmts, field_inits);
    };

    let mut decode_stmts_inner: Vec<proc_macro2::TokenStream> = Vec::new();

    if let syn::Fields::Named(fields) = &data_struct.fields {
        let mut field_index = 0;
        let mut bitfield_section_index = 0;

        while field_index < fields.named.len() {
            let bitfield_section = &struct_info.bitfield_sections.get(bitfield_section_index);

            if bitfield_section
                .is_some_and(|(section, _)| field_index >= section[0] && field_index < section[1])
            {
                let bitfield_section = bitfield_section.unwrap();
                let section = bitfield_section.0;
                let byte_len = bitfield_section.1;
                let section_start = section[0];
                let section_end = section[1];
                let mut bit_offset = 0;

                for field_index in section_start..section_end {
                    let field = &fields.named[field_index];
                    let name = field.ident.clone().unwrap();
                    let name_str = name.to_string();
                    let mut primitive_ty = field.ty.clone();
                    let primitive_ty_str = primitive_ty.to_token_stream().to_string();

                    let field_info = &struct_info.fields[&name_str];
                    let use_default = field_info.use_default;
                    let default_value = &field_info.default_value;
                    let bit_width = field_info.bit_width.unwrap();

                    decode_stmts_inner.clear();

                    let enum_match_stmt = if is_enum_type(&primitive_ty_str) {
                        let enum_info = get_enum_info(&primitive_ty_str).unwrap();
                        primitive_ty = str_to_type(&enum_info.repr_ty);

                        let enum_info = get_enum_info(&primitive_ty_str).unwrap();
                        let enum_ident = Ident::new(&primitive_ty_str, Span::call_site());

                        let stmt = gen_enum_match(&enum_ident, &enum_info);
                        quote! { 
                            let res = { #stmt };
                            let v = match res {
                                Ok(v) => v,
                                Err(_) => return Err(()),
                            };
                        }
                    } else {
                        quote! {}
                    };

                    let shift_decode_stmt = match byte_order {
                        ByteOrder::BE => quote! { (#bit_width - 1 - i) },
                        ByteOrder::LE => quote! { i },
                    };

                    let no_checked_decode_stmt = quote! {
                        let mut v = #primitive_ty::default();

                        for i in 0..#bit_width {
                            let bit_index = #bit_offset + i;
                            let byte_index = *offset + bit_index / 8;
                            let byte = buf[byte_index];
                            let bit = (byte >> (bit_index % 8)) & 1;

                            if bit != 0 {
                                v |= #primitive_ty::from(1u8) << #shift_decode_stmt;
                            }
                        }
                    };

                    if use_default {
                        match default_value {
                            None => decode_stmts_inner.push(quote! {
                                if *offset + (#bit_offset + #bit_width + 7) / 8 > buf.len() {
                                    #primitive_ty::default()
                                } else {
                                    #no_checked_decode_stmt
                                    #enum_match_stmt
                                    v
                                }
                            }),
                            Some(value) => {
                                let ident: Ident = syn::Ident::new(&value, Span::call_site());
                                decode_stmts_inner.push(quote! {
                                    if *offset + (#bit_offset + #bit_width + 7) / 8 > buf.len() {
                                        #ident
                                    } else {
                                        #no_checked_decode_stmt
                                        #enum_match_stmt
                                        v
                                    }
                                });
                            }
                        }
                    } else {
                        decode_stmts_inner.push(quote! {
                            if *offset + (#bit_offset + #bit_width + 7) / 8 > buf.len() {
                                return Err(());
                            }
                            #no_checked_decode_stmt
                            #enum_match_stmt
                            v
                        });
                    };

                    decode_stmts.push(quote! {
                        let #name = { #(#decode_stmts_inner)* };
                    });
                    field_inits.push(quote! { #name });

                    bit_offset += bit_width;
                }

                decode_stmts.push(quote! {
                    *offset += #byte_len;
                });

                field_index = section_end;
                bitfield_section_index += 1;
            } else {
                decode_stmts_inner.clear();

                let field = &fields.named[field_index];
                let name = field.ident.clone().unwrap();
                let name_str = name.to_string();
                let ty = &field.ty;
                let field_info = &struct_info.fields[&name_str];
                let use_default = field_info.use_default;
                let default_value = &field_info.default_value;

                let decode_data_stmt = gen_decode_data(ty, byte_order, field_info);
                decode_stmts_inner.push(quote! {
                    let res = { #decode_data_stmt };
                });

                let default_value_stmt = match default_value {
                    Some(v) => {
                        let ident = Ident::new(v, Span::call_site());
                        quote! { #ident }
                    }
                    None => quote! {
                        let v: #ty = Default::default();
                        v
                    },
                };
                decode_stmts_inner.push(quote! {
                    match res {
                        Ok(v) => v,
                        Err(_) => {
                            if #use_default {
                                #default_value_stmt
                            } else {
                                return Err(());
                            }
                        }
                    }
                });

                decode_stmts.push(quote! {
                    let #name = { #(#decode_stmts_inner)* };
                });
                field_inits.push(quote! { #name });

                field_index += 1;
            }
        }
    }

    (decode_stmts, field_inits)
}

fn decode_enum(
    input: &syn::DeriveInput,
    byte_order: ByteOrder,
    enum_info: &EnumInfo,
) -> Vec<proc_macro2::TokenStream> {
    let mut decode_stmts: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut decode_stmts_inner: Vec<proc_macro2::TokenStream> = Vec::new();

    let repr_ty = str_to_type(&enum_info.repr_ty);
    let stmt =  match byte_order {
        ByteOrder::BE => quote! { #repr_ty::decode_be(buf, offset) },
        ByteOrder::LE => quote! { #repr_ty::decode_le(buf, offset) },
    };

    let enum_match_stmt = gen_enum_match(&input.ident, &enum_info);
    decode_stmts_inner.push(quote! {
        let res = { #stmt };
        match res {
            Ok(v) => {
                let res = { #enum_match_stmt };
                match res {
                    Ok(v) => v,
                    Err(_) => return Err(()),
                }
            }
            Err(_) => return Err(())
        }
    });

    decode_stmts.push(quote! {
        let v = { #(#decode_stmts_inner)* };
    });

    decode_stmts
}

fn gen_enum_match(enum_ident: &syn::Ident, enum_info: &EnumInfo) -> proc_macro2::TokenStream {
    let mut stmts = Vec::new();

    let primitive_ty = str_to_type(&enum_info.repr_ty);

    for (ident, discr) in enum_info.variants.iter() {
        let ident = Ident::new(&ident, Span::call_site());

        let value_expr = match discr {
            Some(expr) => {
                let expr = syn::LitInt::new(&expr, Span::call_site());
                quote! { (#expr) as #primitive_ty }
            }
            None => quote! { (#enum_ident::#ident as #primitive_ty) },
        };

        stmts.push(quote! {
            x if x == #value_expr => Ok(#enum_ident::#ident),
        });
    }

    quote! {
        match v {
            #(#stmts)*
            _ => Err(()),
        }
    }
}

fn gen_decode_data(
    ty: &syn::Type,
    byte_order: ByteOrder,
    field_info: &FieldInfo,
) -> proc_macro2::TokenStream {
    let ty_str = ty.to_token_stream().to_string();

    if is_struct_type(&ty_str) || is_enum_type(&ty_str) {
        match byte_order {
            ByteOrder::BE => quote! { #ty::decode_be(buf, offset) },
            ByteOrder::LE => quote! { #ty::decode_le(buf, offset) },
        }
    } else {
        let decode_stmt = gen_decode_std_data(ty, byte_order, &field_info);
        quote! { #decode_stmt }
    }
}

fn gen_decode_std_data(
    ty: &syn::Type,
    byte_order: ByteOrder,
    field_info: &FieldInfo,
) -> proc_macro2::TokenStream {
    match &ty {
        Type::Array(type_array) => {
            let elem = &type_array.elem;
            let len = &type_array.len;

            if is_fixed_primitive_type(&elem) {
                match byte_order {
                    ByteOrder::BE => quote! { #ty::decode_be(buf, offset) },
                    ByteOrder::LE => quote! { #ty::decode_le(buf, offset) },
                }
            } else {
                let elem_decode_stmt = gen_decode_data(&elem, byte_order, field_info);

                quote! {
                    let mut list = with_capacity(#len);
                    let mut err_index = None;

                    for i in 0..#len {
                        let res = #elem_decode_stmt;
                        match res {
                            Ok(v) => list.push(v),
                            Err(_) => { err_index.get_or_insert(i); }
                        }
                    }

                    if let Some(err_index) = err_index {
                        Err(())
                    } else {
                        Ok(list)
                    }
                }
            }
        }
        Type::Path(type_path) => {
            let ident = type_path.path.segments.last().unwrap().ident.to_string();
            if is_fixed_primitive_type_str(&ident) {
                match byte_order {
                    ByteOrder::BE => quote! { #ty::decode_be(buf, offset) },
                    ByteOrder::LE => quote! { #ty::decode_le(buf, offset) },
                }
            } else if is_str_type(&ident) {
                match &field_info.str_delimiter {
                    Some(str_delimiter) => {
                        let str_delimiter = proc_macro2::Literal::byte_string(str_delimiter.as_slice());
                        quote! { #ty::decode_str(buf, offset, Some(#str_delimiter)) }
                    },
                    None => quote! { #ty::decode_str(buf, offset, None) },
                }
            } else if is_dynamic_list_type(&ident) {
                let len_from_ident = Ident::new(
                    field_info.len_from.as_ref().expect("Vec need len_from"),
                    Span::call_site(),
                );

                let seg = type_path.path.segments.last().unwrap();
                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                        let stmt = gen_decode_data(inner_ty, byte_order, field_info);
                        return quote! {
                            let len = #len_from_ident as usize;
                            let mut list = Vec::with_capacity(len);
                            let mut err_index = None;

                            for i in 0..len {
                                let res = { #stmt };
                                match res {
                                    Ok(v) => list.push(v),
                                    Err(_) => { err_index.get_or_insert(i); }
                                }
                            }

                            if let Some(err_index) = err_index {
                                Err(())
                            } else {
                                Ok(list)
                            }
                        };
                    }
                }

                quote! {}
            } else {
                quote! {}
            }
        }
        _ => todo!(),
    }
}
