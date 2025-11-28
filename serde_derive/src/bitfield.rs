use super::*;

pub struct BitFieldAccum {
    pub fields: Vec<(syn::Ident, syn::Type, usize)>,
    pub total_bits: usize,
    pub started: Option<syn::Ident>,
}

impl BitFieldAccum {
    pub fn new() -> Self {
        Self {
            fields: vec![],
            total_bits: 0,
            started: None,
        }
    }

    pub fn push(&mut self, name: syn::Ident, ty: syn::Type, bit_len: usize) {
        if self.started.is_none() {
            self.started = Some(name.clone());
        }

        self.fields.push((name, ty, bit_len));
        self.total_bits += bit_len;
    }

    pub fn is_active(&self) -> bool {
        self.started.is_some()
    }

    pub fn clear(&mut self) {
        self.fields.clear();
        self.total_bits = 0;
        self.started = None;
    }
}

#[derive(Debug)]
pub struct BitAttr {
    pub bit_len: usize,
    pub bit_end: bool,
}

impl BitAttr {
    pub fn from_field(field: &syn::Field) -> Option<Self> {
        let attrs = &field.attrs;

        let mut bit_len = None;
        let mut bit_end = false;

        for attr in attrs {
            if !attr.path().is_ident("bitfield") {
                continue;
            }

            if let Meta::List(list) = &attr.meta {
                let nested = syn::parse2::<MetaListParser>(list.tokens.clone())
                    .expect("Invalid bits(...) format")
                    .0;

                for meta in nested {
                    match meta {
                        Meta::NameValue(nv) => {
                            if nv.path.is_ident("len") {
                                bit_len = parse_int::<usize>(nv.value);
                            }
                        }
                        Meta::Path(path) => {
                            if path.is_ident("end") {
                                bit_end = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        bit_len.map(|len| BitAttr {
            bit_len: len,
            bit_end,
        })
    }
}