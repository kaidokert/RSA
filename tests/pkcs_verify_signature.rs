use core::str::FromStr;

use digest::consts::{U10, U16, U2, U20};
use digest::{Digest, FixedOutput, HashMarker, OutputSizeUser, Update};
use pkcs8::AssociatedOid;
use rsa::pkcs1v15::VerifyingKey;
use rsa::{BigUint, RsaPublicKey};
use sha1::Sha1;
use signature::Verifier;
use spki::ObjectIdentifier;

#[test]
fn test_verify_signature() {
    let data = b"hello world";
    let e = 3u32;
    let n = 55u32;
    let key = RsaPublicKey::new(n.into(), e.into()).unwrap();
    let verifying_key = VerifyingKey::<Sha1>::new(key);

    let signature = [0u8; 1];
    let refme: &[u8] = signature.as_ref();
    let sig = refme.try_into().unwrap();
    verifying_key.verify(data, &sig).expect("failed to verify");
}

struct FakeHash {}
impl Default for FakeHash {
    fn default() -> Self {
        FakeHash {}
    }
}
// SHA-1 hash of "hello world!"
const SHA1_HASH: [u8; 20] = [
    0xd3, 0x48, 0x6a, 0xe9, 0x13, 0x6e, 0x78, 0x56, 0xbc, 0x42, 0x21, 0x23, 0x85, 0xea, 0x79, 0x70,
    0x94, 0x47, 0x58, 0x02,
];

impl HashMarker for FakeHash {}
impl OutputSizeUser for FakeHash {
    type OutputSize = U20;
}
impl FixedOutput for FakeHash {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        //        out[0] = 1;
        out.copy_from_slice(&SHA1_HASH);
    }
}
impl Update for FakeHash {
    fn update(&mut self, input: &[u8]) {}
}

//const oid : ObjectIdentifier = ObjectIdentifierRef::from_bytes_unchecked(&[1, 2]);

impl AssociatedOid for FakeHash {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.0");
    //const OID : ObjectIdentifier = ObjectIdentifier::from_bytes(&[1, 2]).unwrap();
}

#[test]
fn test_verify_signature_128() {
    let data = b"hello world";
    let e = 3u128;
    let n = 340282366920938463426481119284349108471u128;
    let key = RsaPublicKey::new(n.into(), e.into()).unwrap();
    let verifying_key = VerifyingKey::<FakeHash>::new(key);
    //let verifying_key = VerifyingKey::<Sha1>::new(key);

    let signature = [0u8; 16];
    let refme: &[u8] = signature.as_ref();
    let sig = refme.try_into().unwrap();
    verifying_key.verify(data, &sig).expect("failed to verify");
}

#[test]
fn test_verify_signature_256() {
    let data = b"hello world";
    let e = 3u128;
    // The 256-bit modulus as a decimal string
    let modulus_str =
        "115792089237316195423570985008687907850464877150833151201146682276179249020781";
    // Convert the string to a BigUint
    let n = BigUint::from_str(modulus_str).expect("Failed to parse modulus");
    let key = RsaPublicKey::new(n.into(), e.into()).unwrap();
    let verifying_key = VerifyingKey::<FakeHash>::new(key);
    //let verifying_key = VerifyingKey::<Sha1>::new(key);

    let signature = [0u8; 32];
    let refme: &[u8] = signature.as_ref();
    let sig = refme.try_into().unwrap();
    verifying_key.verify(data, &sig).expect("failed to verify");
}

#[test]
fn test_sha1_hash() {
    let mut hasher = Sha1::new();
    Digest::update(&mut hasher, b"hello world!");
    let result = hasher.finalize();
    println!("SHA-1 Hash: {:x?}", &result[..]);
}
#[test]
fn test_verify_256_again() {
    let data = b"hello world!";
    let mut modulus: [u8; 32] = [
        0xBD, 0xE3, 0x6F, 0x89, 0xE0, 0x61, 0x3B, 0xAB, 0x1E, 0x02, 0x41, 0xFD, 0xD3, 0x40, 0xDE,
        0x82, 0xD7, 0x2F, 0x4E, 0x4F, 0x6F, 0x07, 0x00, 0x4B, 0x24, 0x8C, 0x20, 0x42, 0x81, 0x27,
        0x54, 0xFD,
    ];
    let signature: [u8; 32] = [
        0xB9, 0xB7, 0x39, 0xC4, 0x73, 0x81, 0x09, 0xCF, 0x5B, 0x90, 0x6C, 0x24, 0x8F, 0x35, 0x05,
        0xAF, 0xC3, 0xC7, 0x61, 0x05, 0x22, 0xB2, 0x33, 0xE4, 0xA1, 0x3A, 0x6A, 0x9C, 0xBC, 0x29,
        0xCD, 0xE1,
    ];
    let n = BigUint::from_bytes_be(&modulus);
    let key = RsaPublicKey::new(n.into(), 3_u8.into()).unwrap();

    let refme: &[u8] = signature.as_ref();
    let sig = refme.try_into().unwrap();
    let verifying_key = VerifyingKey::<Sha1>::new_unprefixed(key);
    verifying_key.verify(data, &sig).expect("failed to verify");
}

#[test]
fn test_verify_512_bit() {
    let data = b"hello world!";
    let modulus: [u8; 64] = [
        0x96, 0x9D, 0x03, 0xFF, 0xA9, 0x8D, 0x88, 0x8F, 0x3A, 0xA4, 0xF2, 0xFE, 0xD2, 0x32, 0xE6,
        0x1C, 0x4A, 0xCF, 0x06, 0x63, 0xA9, 0x2F, 0x99, 0x03, 0x4C, 0xF7, 0xB7, 0x24, 0x5A, 0x1A,
        0x1E, 0x5E, 0xAF, 0xA5, 0x65, 0xAF, 0xB9, 0x0B, 0xAB, 0x22, 0x85, 0x71, 0x2F, 0xAA, 0x50,
        0x39, 0x39, 0xA0, 0x65, 0xFB, 0x60, 0xDD, 0x08, 0x28, 0xA3, 0x84, 0xF2, 0x6D, 0x8A, 0xFC,
        0x28, 0x6D, 0xF6, 0xCF,
    ];
    let signature: [u8; 64] = [
        0x45, 0x53, 0xF3, 0xAF, 0x16, 0xAF, 0x63, 0x97, 0xB0, 0xD3, 0x2F, 0x8A, 0xEC, 0xD5, 0x4C,
        0xF1, 0xF3, 0xD0, 0x0C, 0x9F, 0x42, 0xDC, 0x68, 0xCB, 0xD7, 0x05, 0xCE, 0xA5, 0xA9, 0x70,
        0x95, 0x3E, 0xC0, 0xBC, 0x4A, 0x18, 0xED, 0x91, 0xA3, 0x5D, 0x66, 0xEC, 0xDA, 0x4A, 0x83,
        0x32, 0xCF, 0xC3, 0xA3, 0xAB, 0x21, 0xAD, 0x59, 0xB2, 0x2E, 0x87, 0xC2, 0x73, 0xFF, 0x08,
        0x88, 0xDD, 0x4D, 0xE0,
    ];
    let n = BigUint::from_bytes_be(&modulus);
    let key = RsaPublicKey::new(n.into(), 3_u8.into()).unwrap();
    let refme: &[u8] = signature.as_ref();
    let sig = refme.try_into().unwrap();
    let verifying_key = VerifyingKey::<Sha1>::new(key);
    verifying_key.verify(data, &sig).expect("failed to verify");
}
