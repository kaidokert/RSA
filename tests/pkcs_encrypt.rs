use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa_generic::pkcs1v15::EncryptingKey;
use rsa_generic::traits::RandomizedEncryptor;
use rsa_generic::RsaPublicKey;

#[cfg(feature = "fixed-bigint")]
use fixed_bigint::FixedUInt;

#[test]
fn test_encrypt() {
    let e: FixedUInt<u32, 8> = 3u8.into();
    let modulus: [u8; 32] = [
        0xBD, 0xE3, 0x6F, 0x89, 0xE0, 0x61, 0x3B, 0xAB, 0x1E, 0x02, 0x41, 0xFD, 0xD3, 0x40, 0xDE,
        0x82, 0xD7, 0x2F, 0x4E, 0x4F, 0x6F, 0x07, 0x00, 0x4B, 0x24, 0x8C, 0x20, 0x42, 0x81, 0x27,
        0x54, 0xFD,
    ];
    let n = FixedUInt::<u32, 8>::from_be_bytes(&modulus);
    let key = RsaPublicKey::new(n, e).unwrap();
    let encrypting_key = EncryptingKey::new(key);

    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    let data = b"hello world!";
    let mut storage = [0u8; 256];
    let cipher = encrypting_key
        .encrypt_with_rng(&mut rng, data, &mut storage)
        .unwrap();
    println!("cipher: {:x?}", &cipher);
}
