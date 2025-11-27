use bytes::{BufMut, BytesMut};
use serde_lib::{Decode, Decoder, Encode, Encoder};

#[derive(Debug, Encoder, Decoder)]
#[ByteOrder(LE)]
struct P {
    f: bool,
    a: u8,
    b: u32,
    #[bitfield(len = 2)]
    bit1: u8,
    #[bitfield(len = 1)]
    bit2: u8,
    #[bitfield(len = 5, end)]
    bit3: u8,
    len: u16,
    #[len_by_field(len)]
    list: Vec<u8>,
    r: R,
    #[len(2)]
    list2: Vec<u8>,
}

#[derive(Debug, Encoder, Decoder)]
#[ByteOrder(LE)]
struct R {
    a: u8,
    b: u32,
    #[len_by_field(b)]
    list: Vec<u8>,
}

fn main() {
    let mut bytes = BytesMut::new();
    let p = P {
        f: true,
        a: 1,
        b: 0,
        bit1: 1,
        bit2: 1,
        bit3: 1,
        len: 1,
        list: vec![1],
        r: R {
            a: 1,
            b: 1,
            list: vec![5],
        },
        list2: vec![3, 9]
    };
    p.encode(&mut bytes);
    println!("encode {:02X?}", bytes);

    let mut offset = 0;
    let p = P::decode(&bytes, &mut offset);
    println!("{:?}", p);
}
