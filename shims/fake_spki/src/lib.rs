#![no_std]

#[cfg(feature = "alloc")]
pub use real_spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier,
    DecodePublicKey, Document, EncodePublicKey, Error, Result, SignatureAlgorithmIdentifier,
    SignatureBitStringEncoding,
};

#[cfg(feature = "alloc")]
pub mod der {
    pub use real_spki::der::{Any, AnyRef, Result};

    pub mod asn1 {
        pub use real_spki::der::asn1::BitString;
    }
}

#[cfg(not(feature = "alloc"))]
pub use real_spki::{
    AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier, DecodePublicKey, Error, Result,
    SignatureAlgorithmIdentifier,
};

#[cfg(not(feature = "alloc"))]
pub struct AlgorithmIdentifierOwned {}

#[cfg(not(feature = "alloc"))]
pub mod der {
    pub use real_spki::der::{AnyRef, Result};

    pub struct Any {}

    pub mod asn1 {
        use super::Result;

        pub struct BitString {}

        impl BitString {
            pub fn new(_unused_bits: u8, _bytes: impl AsRef<[u8]>) -> Result<Self> {
                todo!()
            }
        }
    }
}

#[cfg(not(feature = "alloc"))]
pub trait SignatureBitStringEncoding {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString>;
}

#[cfg(not(feature = "alloc"))]
pub struct Document {}

#[cfg(not(feature = "alloc"))]
pub trait EncodePublicKey {
    fn to_public_key_der(&self) -> Result<Document>;
}
