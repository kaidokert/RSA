//! `RSASSA-PKCS1-v1_5` signatures.

use crate::algorithms::pad::uint_to_be_pad;

/// `RSASSA-PKCS1-v1_5` signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Clone, PartialEq, Eq)]
pub struct Signature<T> {
    pub(super) inner: T,
    pub(super) len: usize,
}

#[cfg(test)]
mod tests {}
