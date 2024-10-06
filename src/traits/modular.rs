use num_traits::{FromBytes, PrimInt, ToBytes, Unsigned, WrappingAdd, WrappingSub};
use zeroize::DefaultIsZeroes;
// Marker trait for types that can be used as unsigned modular integers.
pub trait UnsignedModularInt:
    PrimInt
    + Unsigned
    + WrappingAdd
    + WrappingSub
    + PartialEq
    + ToBytes
    + FromBytes
    + DefaultIsZeroes
    + core::fmt::Debug
{
    fn bits(&self) -> usize {
        let mut count = 0;
        let mut value = *self;

        while value != Self::zero() {
            value = value >> 1;
            count += 1;
        }

        count
    }
    fn is_even(&self) -> bool {
        *self & Self::one() == Self::zero()
    }
}

impl<T> UnsignedModularInt for T where
    T: PrimInt
        + Unsigned
        + WrappingAdd
        + WrappingSub
        + PartialEq
        + ToBytes
        + FromBytes
        + DefaultIsZeroes
        + core::fmt::Debug
{
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
}
