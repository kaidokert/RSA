//! Generate prime components for the RSA Private Key

use num_traits::Zero;
use rand_core::CryptoRngCore;

use crate::{
    algorithms::rsa::{compute_modulus, compute_private_exponent_euler_totient},
    errors::{Error, Result},
};

use crate::traits::UnsignedModularInt;

pub struct RsaPrivateKeyComponents<'a, T>
where
    T: UnsignedModularInt,
{
    pub n: T,
    pub e: T,
    pub d: T,
    pub primes: &'a [T],
}

/// Generates a multi-prime RSA keypair of the given bit size, public exponent,
/// and the given random source, as suggested in [1]. Although the public
/// keys are compatible (actually, indistinguishable) from the 2-prime case,
/// the private keys are not. Thus it may not be possible to export multi-prime
/// private keys in certain formats or to subsequently import them into other
/// code.
///
/// Table 1 in [2] suggests maximum numbers of primes for a given size.
///
/// [1]: https://patents.google.com/patent/US4405829A/en
/// [2]: http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
pub(crate) fn generate_multi_prime_key_with_exp<'a, T, R: CryptoRngCore + ?Sized>(
    rng: &mut R,
    nprimes: usize,
    bit_size: usize,
    exp: &T,
) -> Result<RsaPrivateKeyComponents<'a, T>>
where
    T: UnsignedModularInt,
{
    if nprimes < 2 {
        return Err(Error::NprimesTooSmall);
    }
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::FromPrimitive;
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

    const EXP: u64 = 65537;

    #[test]
    #[ignore]
    fn test_impossible_keys() {
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        todo!()
    }

    macro_rules! key_generation {
        ($name:ident, $multi:expr, $size:expr) => {
            #[test]
            #[ignore]
            fn $name() {
                let mut rng = ChaCha8Rng::from_seed([42; 32]);
                todo!()
            }
        };
    }

    key_generation!(key_generation_128, 2, 128);
    key_generation!(key_generation_1024, 2, 1024);

    key_generation!(key_generation_multi_3_256, 3, 256);

    key_generation!(key_generation_multi_4_64, 4, 64);

    key_generation!(key_generation_multi_5_64, 5, 64);
    key_generation!(key_generation_multi_8_576, 8, 576);
    // TODO: reenable, currently slow
    // key_generation!(key_generation_multi_16_1024, 16, 1024);
}
