//! PKCS#1 and PKCS#8 encoding support.
//!
//! Note: PKCS#1 support is achieved through a blanket impl of the
//! `pkcs1` crate's traits for types which impl the `pkcs8` crate's traits.

use crate::{
    traits::{PrivateKeyParts, PublicKeyParts, UnsignedModularInt},
    RsaPrivateKey, RsaPublicKey,
};
use core::convert::{TryFrom, TryInto};
use pkcs8::{
    der::{asn1::OctetStringRef, Encode},
    ObjectIdentifier,
};
use zeroize::Zeroizing;

/// ObjectID for the RSA PSS keys
pub const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// Verify that the `AlgorithmIdentifier` for a key is correct.
pub(crate) fn verify_algorithm_id(
    algorithm: &pkcs8::AlgorithmIdentifierRef,
) -> pkcs8::spki::Result<()> {
    match algorithm.oid {
        pkcs1::ALGORITHM_OID => {
            if algorithm.parameters_any()? != pkcs8::der::asn1::Null.into() {
                return Err(pkcs8::spki::Error::KeyMalformed);
            }
        }
        ID_RSASSA_PSS => {
            if algorithm.parameters.is_some() {
                return Err(pkcs8::spki::Error::KeyMalformed);
            }
        }
        _ => return Err(pkcs8::spki::Error::OidUnknown { oid: algorithm.oid }),
    };

    Ok(())
}

impl<T> TryFrom<pkcs8::PrivateKeyInfoRef<'_>> for RsaPrivateKey<T>
where
    T: UnsignedModularInt,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        verify_algorithm_id(&private_key_info.algorithm)?;

        let pkcs1_key = pkcs1::RsaPrivateKey::try_from(private_key_info.private_key)?;

        // Multi-prime RSA keys not currently supported
        if pkcs1_key.version() != pkcs1::Version::TwoPrime {
            return Err(pkcs1::Error::Version.into());
        }

        todo!()
    }
}

impl<T> TryFrom<pkcs8::SubjectPublicKeyInfoRef<'_>> for RsaPublicKey<T>
where
    T: UnsignedModularInt,
{
    type Error = pkcs8::spki::Error;

    fn try_from(spki: pkcs8::SubjectPublicKeyInfoRef<'_>) -> pkcs8::spki::Result<Self> {
        verify_algorithm_id(&spki.algorithm)?;

        let pkcs1_key = pkcs1::RsaPublicKey::try_from(
            spki.subject_public_key
                .as_bytes()
                .ok_or(pkcs8::spki::Error::KeyMalformed)?,
        )?;
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore]
    fn test_try_from_publikey() {
        todo!()
    }
}
