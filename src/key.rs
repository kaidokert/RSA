use num_traits::{Num, One, Unsigned, Zero};

/// Represents the public part of an RSA key.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RsaPublicKey<T>
where
    T: Num + Unsigned + Zero + One + Clone + PartialEq + Eq,
{
    /// Modulus: product of prime numbers `p` and `q`
    n: T,
    /// Public exponent: power to which a plaintext message is raised in
    /// order to encrypt it.
    ///
    /// Typically 0x10001 (65537)
    e: T,
}
