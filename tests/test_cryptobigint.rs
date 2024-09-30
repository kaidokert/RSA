use crypto_bigint::U512;
use num_traits::FromBytes;
use rsa_generic::traits::UnsignedModularInt;
use rsa_generic::RsaPublicKey;

fn call_with_unsigned_modular_int<T: UnsignedModularInt>(x: T) -> T {
    x
}

#[test]
fn test_with_crypto_bigint() {
    let x = U512::from(42u32);
    let y = U512::from(42u32);
    assert_eq!(x, y);
    call_with_unsigned_modular_int(x);
}

#[test]
fn test_encrypt() {
    let e = U512::from(3u32);
    let modulus: [u8; 32] = [
        0xBD, 0xE3, 0x6F, 0x89, 0xE0, 0x61, 0x3B, 0xAB, 0x1E, 0x02, 0x41, 0xFD, 0xD3, 0x40, 0xDE,
        0x82, 0xD7, 0x2F, 0x4E, 0x4F, 0x6F, 0x07, 0x00, 0x4B, 0x24, 0x8C, 0x20, 0x42, 0x81, 0x27,
        0x54, 0xFD,
    ];
    let n = U512::from_be_slice(&modulus);
    let key = RsaPublicKey::new(n, e).unwrap();
}
