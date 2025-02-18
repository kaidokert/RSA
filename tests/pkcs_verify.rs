use sha1::Sha1;
use signature::Verifier;

use rsa_heapless::pkcs1v15::VerifyingKey;
use rsa_heapless::RsaPublicKey;

use rsa_heapless::traits::UnsignedModularInt;
use rsa_heapless::pkcs1v15::Signature;

// "Create" function factored out because every bignum library
// has a different way of converting a byte slice to a bignum.
type CreateKey<'a, T> = &'a dyn Fn(&[u8]) -> T;

fn test_verify_512_bit<T>(create_key: CreateKey<T>) -> Result<(), i8>
where 
    T: UnsignedModularInt + From<u8>,
    for<'a> Signature<T>: TryFrom<&'a [u8]> + core::fmt::Debug
 {
    let data = b"hello world!";
    // 512-bit key and signature
    let modulus: [u8; 64] = [ //big-endian
        0x96, 0x9D, 0x03, 0xFF, 0xA9, 0x8D, 0x88, 0x8F, 0x3A, 0xA4, 0xF2, 0xFE, 0xD2, 0x32, 0xE6,
        0x1C, 0x4A, 0xCF, 0x06, 0x63, 0xA9, 0x2F, 0x99, 0x03, 0x4C, 0xF7, 0xB7, 0x24, 0x5A, 0x1A,
        0x1E, 0x5E, 0xAF, 0xA5, 0x65, 0xAF, 0xB9, 0x0B, 0xAB, 0x22, 0x85, 0x71, 0x2F, 0xAA, 0x50,
        0x39, 0x39, 0xA0, 0x65, 0xFB, 0x60, 0xDD, 0x08, 0x28, 0xA3, 0x84, 0xF2, 0x6D, 0x8A, 0xFC,
        0x28, 0x6D, 0xF6, 0xCF,
    ];
    let signature: [u8; 64] = [ //big-endian
        0x45, 0x53, 0xF3, 0xAF, 0x16, 0xAF, 0x63, 0x97, 0xB0, 0xD3, 0x2F, 0x8A, 0xEC, 0xD5, 0x4C,
        0xF1, 0xF3, 0xD0, 0x0C, 0x9F, 0x42, 0xDC, 0x68, 0xCB, 0xD7, 0x05, 0xCE, 0xA5, 0xA9, 0x70,
        0x95, 0x3E, 0xC0, 0xBC, 0x4A, 0x18, 0xED, 0x91, 0xA3, 0x5D, 0x66, 0xEC, 0xDA, 0x4A, 0x83,
        0x32, 0xCF, 0xC3, 0xA3, 0xAB, 0x21, 0xAD, 0x59, 0xB2, 0x2E, 0x87, 0xC2, 0x73, 0xFF, 0x08,
        0x88, 0xDD, 0x4D, 0xE0,
    ];
    let n = create_key(&modulus);
    let key = RsaPublicKey::new(n, 3u8.into()).unwrap();
    let refme: &[u8] = signature.as_ref();
    let sig = refme.try_into().map_err(|_| -1)?;
    let verifying_key = VerifyingKey::<Sha1, _>::new(key);

    verifying_key.verify(data, &sig).expect("failed to verify");
    Ok(())
}

#[test]
fn test_with_crypto_bigint() {
    test_verify_512_bit::<crypto_bigint::U512>(
        &|bytes| 
        crypto_bigint::U512::from_be_slice(bytes)).unwrap();
}

#[test]
fn test_with_fixed_bigint() {
    test_verify_512_bit::<fixed_bigint::FixedUInt<u32, 16>>(
        &|bytes| 
        fixed_bigint::FixedUInt::<u32, 16>::from_be_bytes(bytes)
    ).unwrap();
}

#[test]
fn test_with_fixed_bigint_8_bit_math() {
    test_verify_512_bit::<fixed_bigint::FixedUInt<u8, 64>>(
        &|bytes| 
        fixed_bigint::FixedUInt::<u8, 64>::from_be_bytes(bytes)
    ).unwrap();
}

#[test]
#[ignore]
fn test_with_bnum() {
    test_verify_512_bit::<bnum::types::U512>(
        &|bytes| bnum::types::U512::from_be_slice(bytes).expect("failed to convert")
    ).unwrap();
}