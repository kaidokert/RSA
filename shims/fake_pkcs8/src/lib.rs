#![no_std]

pub use const_oid::ObjectIdentifier;
pub use real_pkcs8::{
    AlgorithmIdentifierRef, AssociatedOid, Error, PrivateKeyInfoRef, Result,
    SubjectPublicKeyInfoRef,
};


pub mod spki {
    #[cfg(feature = "alloc")]
    pub use ::spki::{
        AlgorithmIdentifierOwned, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier,
        DecodePublicKey, Document, DynSignatureAlgorithmIdentifier, EncodePublicKey, Error,
        Result, SignatureAlgorithmIdentifier,
    };

    #[cfg(not(feature = "alloc"))]
    pub use ::spki::{
        AlgorithmIdentifierOwned, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier,
        DecodePublicKey, Document, EncodePublicKey, Error, Result, SignatureAlgorithmIdentifier,
    };

    pub mod der {
        pub use ::spki::der::{Any, AnyRef, Result};
    }
}

pub mod der {
    pub use real_pkcs8::der::{Encode, Decode};

    pub mod asn1 {
        pub use real_pkcs8::der::asn1::{BitStringRef, Null, OctetStringRef};
    }
}

#[cfg(feature = "alloc")]
pub use real_pkcs8::{DecodePrivateKey, DecodePublicKey, Document, EncodePrivateKey, SecretDocument, LineEnding};

#[cfg(feature = "alloc")]
pub use spki::EncodePublicKey;

#[cfg(not(feature = "alloc"))]
pub struct SecretDocument {}

#[cfg(not(feature = "alloc"))]
pub trait EncodePrivateKey {
    fn to_pkcs8_der(&self) -> Result<SecretDocument>;
}

#[cfg(not(feature = "alloc"))]
pub trait EncodePublicKey {
    fn to_public_key_der(&self) -> spki::Result<Document>;
}

#[cfg(not(feature = "alloc"))]
pub struct Document {}
