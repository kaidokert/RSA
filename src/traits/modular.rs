use core::borrow::Borrow;

use crypto_bigint::BoxedUint;
use zeroize::Zeroize;

pub trait NumBytes: Borrow<[u8]> + Zeroize + AsRef<[u8]> {}

impl NumBytes for [u8; 1] {}

pub trait UnsignedModularInt: Zeroize {
    type Bytes: NumBytes;
    fn leading_zeros(&self) -> u32;
    fn to_be_bytes(&self) -> Self::Bytes;
}

#[cfg(not(feature = "alloc"))]
pub struct NoAllocBytes(pub(crate) crypto_bigint::ByteBoxHolder<u8>);

impl UnsignedModularInt for u8 {
    type Bytes = [u8; 1];

    fn leading_zeros(&self) -> u32 {
        u8::leading_zeros(*self)
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        u8::to_be_bytes(*self)
    }
}

#[cfg(feature = "alloc")]
impl NumBytes for alloc::boxed::Box<[u8]> {}

#[cfg(feature = "alloc")]
impl UnsignedModularInt for BoxedUint {
    type Bytes = alloc::boxed::Box<[u8]>;

    fn leading_zeros(&self) -> u32 {
        self.leading_zeros()
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        self.as_words()
            .iter()
            .rev()
            .flat_map(|word| word.to_be_bytes())
            .collect::<alloc::vec::Vec<u8>>()
            .into_boxed_slice()
    }
}

#[cfg(not(feature = "alloc"))]
impl Borrow<[u8]> for NoAllocBytes {
    fn borrow(&self) -> &[u8] {
        self.as_ref()
    }
}

#[cfg(not(feature = "alloc"))]
impl AsRef<[u8]> for NoAllocBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0[0..]
    }
}

#[cfg(not(feature = "alloc"))]
impl Zeroize for NoAllocBytes {
    fn zeroize(&mut self) {}
}

#[cfg(not(feature = "alloc"))]
impl NumBytes for NoAllocBytes {}

#[cfg(not(feature = "alloc"))]
impl UnsignedModularInt for BoxedUint {
    type Bytes = NoAllocBytes;

    fn leading_zeros(&self) -> u32 {
        self.leading_zeros()
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        NoAllocBytes(self.to_be_bytes())
    }
}
