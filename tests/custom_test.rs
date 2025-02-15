mod subtests;

use subtests::rsa7::rsa_signature_verify as rsa7_test;
use subtests::rsa_h::rsa_signature_verify as rsa_h_test;

#[test]
fn test_512_8_bit() {
    if rsa_h_test::<u8, 64>().is_ok() {
        println!("RSA signature check passed [8-bit]!");
    } else {
        println!("RSA signature check failed [8-bit]!");
    }
}

#[test]
fn test_768_32_bit() {
    if rsa7_test::<u32, 16>().is_ok() {
        println!("RSA signature check passed [32-bit]!");
    } else {
        println!("RSA signature check failed [32-bit]!");
    }
}
