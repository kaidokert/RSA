use num_traits::{PrimInt, Unsigned, WrappingAdd, WrappingSub};

// Marker trait for types that can be used as unsigned modular integers.
pub trait UnsignedModularInt: PrimInt + Unsigned + WrappingAdd + WrappingSub + PartialEq {
    fn bits(&self) -> usize {
        todo!()
    }
    fn is_even(&self) -> bool {
        todo!()
    }
}

impl<T> UnsignedModularInt for T where T: PrimInt + Unsigned + WrappingAdd + WrappingSub + PartialEq {}
