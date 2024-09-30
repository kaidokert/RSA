use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::pkcs1v15::EncryptingKey;
use rsa::traits::RandomizedEncryptor;
use rsa::{BigUint, RsaPublicKey};
#[test]
fn test_encrypt() {
    let mut modulus: [u8; 32] = [
        0xBD, 0xE3, 0x6F, 0x89, 0xE0, 0x61, 0x3B, 0xAB, 0x1E, 0x02, 0x41, 0xFD, 0xD3, 0x40, 0xDE,
        0x82, 0xD7, 0x2F, 0x4E, 0x4F, 0x6F, 0x07, 0x00, 0x4B, 0x24, 0x8C, 0x20, 0x42, 0x81, 0x27,
        0x54, 0xFD,
    ];
    let n = BigUint::from_bytes_be(&modulus);
    let key = RsaPublicKey::new(n.into(), 3_u8.into()).unwrap();
    let encrypting_key = EncryptingKey::new(key);

    let mut rng = ChaCha8Rng::from_seed([42; 32]);

    let data = b"hello world!";
    let mut storage_buffer = [0u8; 256];
    let cipher = encrypting_key.encrypt_with_rng(&mut rng,data).unwrap();
    println!("cipher: {:x?}", &cipher);
}