use sha1::{Sha1, Digest};

#[test]
fn test_sha1_hash() {
    let mut hasher = Sha1::new();
    hasher.update(b"hello world!");
    let result = hasher.finalize();
    println!("SHA-1 Hash: {:x?}", result);
}
