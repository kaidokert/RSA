//! Small unblinded, non-CRT private operation through the public hazmat API.

use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;
use crypto_bigint::{modular::BoxedMontyParams, BoxedUint};
use rsa::{
    hazmat::rsa_decrypt,
    traits::{NonZero, PrivateKeyParts, PublicKeyParts},
    RsaPublicKey,
};
use zeroize::Zeroizing;

#[checkct]
pub fn rsa_decrypt_unblinded_non_crt_128() {
    // SAFETY: This independent, single-threaded analysis has no live allocations.
    unsafe { crate::allocator::reset() };

    // Public modulus (2^64 - 59) * (2^64 - 83), with fixed 128-bit precision.
    let n = BoxedUint::from_be_hex("FFFFFFFFFFFFFF720000000000001321", 128).unwrap();
    let public = RsaPublicKey::new(n, BoxedUint::from(65537u64)).unwrap();

    let mut bytes = [0u8; 16];
    PrivateRng.fill_bytes(&mut bytes);
    let key = NonCrtKey {
        public,
        d: Zeroizing::new(BoxedUint::from_be_slice(&bytes, 128).unwrap()),
    };

    PublicRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f; // Public ciphertext below 2^127 is below the modulus.
    let c = BoxedUint::from_be_slice(&bytes, 128).unwrap();

    // `None` disables blinding. The API processes all 128 exponent bits, including leading zeros.
    // The fixture below selects the non-CRT path.
    let m = rsa_decrypt::<PrivateRng>(None, &key, &c).unwrap();
    black_box(m.as_limbs());
    drop(m);
    drop(key);
}

// Leave `d` unconstrained without including key validation or CRT precomputation in the analysis.
// This fixture checks the private operation's arithmetic, not whether the supplied exponent forms a
// valid RSA key.
struct NonCrtKey {
    public: RsaPublicKey,
    d: Zeroizing<BoxedUint>,
}

impl PublicKeyParts<BoxedUint> for NonCrtKey {
    type MontyParams = BoxedMontyParams;

    fn n(&self) -> &NonZero<BoxedUint> {
        self.public.n()
    }

    fn e(&self) -> &BoxedUint {
        self.public.e()
    }

    fn n_params(&self) -> &BoxedMontyParams {
        self.public.n_params()
    }
}

// The CRT accessors default to `None`, which selects the non-CRT path.
impl PrivateKeyParts<BoxedUint> for NonCrtKey {
    fn d(&self) -> &BoxedUint {
        &self.d
    }
}
