//! Useful algorithms related to RSA.

// MGF1 is needed by both OAEP (encrypt) and PSS (verify) on the public-key
// path; ungated so it can be exercised in no_alloc builds without pulling
// in the rest of the `full` surface.
pub(crate) mod mgf;

#[cfg(feature = "private-key")]
pub(crate) mod generate;
pub(crate) mod oaep;
pub(crate) mod pad;
pub(crate) mod pkcs1v15;
pub(crate) mod pss;
pub(crate) mod rsa;
