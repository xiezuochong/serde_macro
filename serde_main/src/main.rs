use bytes::{BufMut, BytesMut};
use serde_lib::{Decode, Decoder, Encode, Encoder};

#[derive(Debug, Encoder, Decoder)]
#[ByteOrder(LE)]
struct P {
    // f: bool,
    // a: u8,
    b: u32,
    // #[bitfield(len = 2)]
    // bit1: u8,
    // #[bitfield(len = 1)]
    // bit2: u8,
    // #[bitfield(len = 5, end)]
    // bit3: u8,
    len: u16,
    #[delimiter(0)]
    str1: String,
}


fn main() {
    let mut bytes = BytesMut::new();
    let p = P {
        // f: true,
        // a: 1,
        b: 0,
        // bit1: 1,
        // bit2: 1,
        // bit3: 1,
        len: 1,
        str1: "123".to_string(),
    };
    p.encode(&mut bytes);
    println!("encode {:02X?}", bytes);

    bytes.put_u8(0);

    let mut offset = 0;
    let res = P::decode(bytes.as_ref(), &mut offset);

    println!("{:?}", res);
}
