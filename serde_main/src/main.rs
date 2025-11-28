use bytes::{BufMut, BytesMut};
use serde_lib::{Encode, Encoder};

#[derive(Debug, Encoder)]
#[ByteOrder(LE)]
struct P<'a> {
    // f: bool,
    // a: u8,
    // b: u32,
    // #[bitfield(len = 2)]
    // bit1: u8,
    // #[bitfield(len = 1)]
    // bit2: u8,
    // #[bitfield(len = 5, end)]
    // bit3: u8,
    // len: u16,
    list: Vec<u8>,
    r: R,
    list2: Vec<u8>,
    str: &'a str,
    str_list: Vec<String>,
}

#[derive(Debug, Encoder)]
#[ByteOrder(LE)]
struct R {
    a: u8,
    list: Vec<u8>,
}

fn main() {
    let mut bytes = BytesMut::new();
    let p = P {
        // f: true,
        // a: 1,
        // b: 0,
        // bit1: 1,
        // bit2: 1,
        // bit3: 1,
        // len: 1,
        list: vec![1],
        r: R {
            a: 1,
            list: vec![5],
        },
        list2: vec![3, 9],
        str: "123",
        str_list: vec!["1".to_string(), "456".to_string()],
    };
    p.encode(&mut bytes);
    println!("encode {:02X?}", bytes);
}
