use num_traits::{FromBytes, PrimInt, ToBytes, Unsigned, WrappingAdd, WrappingSub};
use zeroize::DefaultIsZeroes;
// Marker trait for types that can be used as unsigned modular integers.
pub trait UnsignedModularInt:
    PrimInt
    // This provides gcd()
    // + num_integer::Integer
    + Unsigned
    + WrappingAdd
    + WrappingSub
    + PartialEq
    + ToBytes
    + FromBytes
    + DefaultIsZeroes
    + core::ops::ShrAssign<usize>
    + core::ops::RemAssign
    + core::ops::MulAssign
    + core::fmt::Debug
{
    fn bits(&self) -> usize {
        let mut count = 0;
        let mut value = *self;

        while value != Self::zero() {
            value >>= 1;
            count += 1;
        }

        count
    }
    fn is_even(&self) -> bool {
        *self & Self::one() == Self::zero()
    }
    fn bits_precision(&self) -> u32 {
        // we can check the size of ToBytes
        (core::mem::size_of::<<Self as ToBytes>::Bytes>() * 8) as u32
    }
    fn widen(&self, bits: u32) -> Self {
        // no-op
        *self
    }
    fn shorten(&self, bits: u32) -> Self {
        // no-op
        *self
    }
    fn one_with_precision(bits: u32) -> Self {
        Self::one()
    }
    fn rem_vartime(&self, other: &Self) -> Self {
        todo!()
    }
    fn gcd(&self, other: &Self) -> Self {
        todo!()
    }
}

impl<T> UnsignedModularInt for T where
    T: PrimInt
    // This provides gcd()
    // + num_integer::Integer
        + Unsigned
        + WrappingAdd
        + WrappingSub
        + PartialEq
        + ToBytes
        + FromBytes
        + DefaultIsZeroes
        + core::ops::ShrAssign<usize>
        + core::ops::RemAssign
        + core::ops::MulAssign
        + core::fmt::Debug
{
}

#[derive(Debug, Clone)]
pub struct MontyParams<T>
where
    T: UnsignedModularInt,
{
    modulus: T,
}

impl<T> MontyParams<T>
where
    T: UnsignedModularInt,
{
    pub fn new(n: T) -> Self {
        Self { modulus: n }
    }
    pub fn modulus(&self) -> &T {
        &self.modulus
    }
    pub fn bits_precision(&self) -> u32 {
        self.modulus.bits_precision()
    }

}

#[derive(Debug, Clone)]
pub struct MontyForm<T>
where
    T: UnsignedModularInt,
{
    _phantom: core::marker::PhantomData<T>,
}

impl<T> MontyForm<T>
where
    T: UnsignedModularInt,
{
    pub fn new(n: T, p: MontyParams<T>) -> Self {
        Self { _phantom: core::marker::PhantomData }
    }
    pub fn pow(&self, exponent: &T) -> Self {
        todo!()
    }
    pub fn retrieve(&self) -> T {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits() {
        assert_eq!(1u32.bits(), 1);
        assert_eq!(2u32.bits(), 2);
        assert_eq!(55u32.bits(), 6);
        assert_eq!(0x8000000000000000_u64.bits(), 64);
        assert_eq!(0xFFFFFFFFFFFFFFFF_u64.bits(), 64);
    }
    #[test]
    fn test_is_even() {
        assert_eq!(1u32.is_even(), false);
        assert_eq!(2u32.is_even(), true);
        assert_eq!(55u32.is_even(), false);
        assert_eq!(0x8000000000000000_u64.is_even(), true);
        assert_eq!(0xFFFFFFFFFFFFFFFF_u64.is_even(), false);
    }

    #[test]
    fn test_n_bits_precision() {
        assert_eq!(1u32.bits_precision(), 32);
        assert_eq!(2u32.bits_precision(), 32);
        assert_eq!(55u32.bits_precision(), 32);
        assert_eq!(0x8000000000000000_u64.bits_precision(), 64);
        assert_eq!(0xFFFFFFFFFFFFFFFF_u64.bits_precision(), 64);
    }
}
