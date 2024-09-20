use rsa_generic::pkcs1v15::verify;
use rsa_generic::pkcs1v15::VerifyingKey;
use rsa_generic::RsaPublicKey;

#[test]
fn test_verify_signature() {
    let data = b"hello world";
    let e = 3u8;
    let n = 55u8;
    let key = RsaPublicKey::new(n, e).unwrap();
    //let verifying_key = VerifyingKey::<u8,_>::new(key);

    // Verify
    let signature = [0u8; 128];
    let refme: &[u8] = signature.as_ref();
    //let sig = refme.try_into().unwrap();

    //verifying_key.verify(data, &sig).expect("failed to verify");
    let prefix = [0u8; 2];
    verify(&key, &prefix, &signature, &33u8, 1);
}
