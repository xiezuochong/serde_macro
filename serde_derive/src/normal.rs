use super::*;

pub fn gen_encode_for_normal(
    name: &syn::Ident,
    ty: &Type,
    byte_order: ByteOrder,
) -> proc_macro2::TokenStream {
    match ty {
        Type::Array(_) => {
            quote! { buf.extend_from_slice(&self.#name); }
        }
        Type::Reference(type_ref) => {
            if let Type::Slice(_) = &*type_ref.elem {
                quote! { buf.extend_from_slice(&self.#name); }
            } else {
                quote! {}
            }
        }
        Type::Path(tp) => {
            let ident = &tp.path.segments.last().unwrap().ident;
            match ident.to_string().as_str() {
                "bool" => quote! { buf.put_u8(self.#name as u8); },
                "u8" => quote! { buf.put_u8(self.#name); },
                "i8" => quote! { buf.put_i8(self.#name); },
                "u16" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_u16_be(self.#name); },
                    ByteOrder::LE => quote! { buf.put_u16_le(self.#name); },
                },
                "u32" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_u32_be(self.#name); },
                    ByteOrder::LE => quote! { buf.put_u32_le(self.#name); },
                },
                "i32" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_i32_be(self.#name); },
                    ByteOrder::LE => quote! { buf.put_i32_le(self.#name); },
                },
                "f32" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_f32_be(self.#name); },
                    ByteOrder::LE => quote! { buf.put_f32_le(self.#name); },
                },
                "u64" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_u64_be(self.#name); },
                    ByteOrder::LE => quote! { buf.put_u64_le(self.#name); },
                },
                "i64" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_i64_be(self.#name); },
                    ByteOrder::LE => quote! { buf.put_i64_le(self.#name); },
                },
                "f64" => match byte_order {
                    ByteOrder::BE => quote! { buf.put_f64_be(self.#name); },
                    ByteOrder::LE => quote! { buf.put_f64_le(self.#name); },
                },
                "Vec" => quote! { buf.extend_from_slice(&self.#name); },
                _ => quote! {},
            }
        }

        _ => quote! {},
    }
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
