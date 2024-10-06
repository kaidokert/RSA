use crypto_bigint::U512;
use num_traits::FromBytes;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa_heapless::pkcs1v15::EncryptingKey;
use rsa_heapless::traits::RandomizedEncryptor;
use rsa_heapless::traits::UnsignedModularInt;
use rsa_heapless::RsaPublicKey;

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
    let modulus: [u8; 64] = [
        0x96, 0x9D, 0x03, 0xFF, 0xA9, 0x8D, 0x88, 0x8F, 0x3A, 0xA4, 0xF2, 0xFE, 0xD2, 0x32, 0xE6,
        0x1C, 0x4A, 0xCF, 0x06, 0x63, 0xA9, 0x2F, 0x99, 0x03, 0x4C, 0xF7, 0xB7, 0x24, 0x5A, 0x1A,
        0x1E, 0x5E, 0xAF, 0xA5, 0x65, 0xAF, 0xB9, 0x0B, 0xAB, 0x22, 0x85, 0x71, 0x2F, 0xAA, 0x50,
        0x39, 0x39, 0xA0, 0x65, 0xFB, 0x60, 0xDD, 0x08, 0x28, 0xA3, 0x84, 0xF2, 0x6D, 0x8A, 0xFC,
        0x28, 0x6D, 0xF6, 0xCF,
    ];
    let n = U512::from_be_slice(&modulus);
    let key = RsaPublicKey::new(n, e).unwrap();
    let encrypting_key = EncryptingKey::new(key);

    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    let data = b"hello world!";
    let mut storage = [0u8; 256];
    /*
       let cipher = encrypting_key
           .encrypt_with_rng(&mut rng, data, &mut storage)
           .unwrap();
    */
}
