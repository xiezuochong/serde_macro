#[cfg(feature = "derive")]
pub use serde_derive::{Decoder, Encoder};

pub use byte;
pub use bytes::BytesMut;

pub trait Encode: Sized {
    fn encode(&self, buf: &mut BytesMut);
}

pub trait Decode: Sized {
    fn decode(buf: &[u8], offset: &mut usize) -> Result<Self, byte::Error>;
}

/// 根据 bit_num 生成掩码，低 bit_num 位为 1，高位为 0
pub fn mask_for_bits<T>(bit_num: u32) -> T
where
    T: Copy
        + std::ops::Shl<u32, Output = T>
        + std::ops::Sub<Output = T>
        + std::ops::Not<Output = T>
        + From<u8>,
{
    let width = std::mem::size_of::<T>() as u32 * 8;
    if bit_num == 0 {
        T::from(0)
    } else if bit_num >= width {
        !T::from(0)
    } else {
        (T::from(1) << bit_num) - T::from(1)
    }
}
