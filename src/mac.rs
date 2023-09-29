use hex_literal::hex;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};

pub fn test() {
    let mut hmac = Hmac::<Sha256>::new_from_slice(b"key").expect("HMAC can take key of any size");
    hmac.update(b"some msg");

    let result = hmac.finalize();

    println!("{:x?}", hex::encode(result.into_bytes()));

    println!("kdf: ");

    // let mut hmac = Hmac::<Sha256>::new_from_slice(b"12345").expect("HMAC can take key of any size");
    // hmac.update(b"sample message");

    // let result = hmac.finalize();

    // println!("kdf: {:x?}", hex::encode(result.into_bytes()));
    // https://cryptobook.nakov.com/mac-and-key-derivation/hmac-and-key-derivation#hmac-calculation-example

    let hk = Hkdf::<Sha256>::new(None, b"12345");

    // Output Key Material
    let mut okm = [0u8; 42];
    hk.expand(b"sample message", &mut okm)
        .expect("42 is a valid length for Sha256 to output");

    println!("{:x?}", hex::encode(okm));

    println!("Exercises: Calculate HMAC: ");
    let mut hmac =
        Hmac::<Sha384>::new_from_slice(b"cryptography").expect("HMAC can take key of any size");
    hmac.update(b"hello");

    let result = hmac.finalize();
    assert_eq!(
        result.into_bytes()[..],
        hex!("83d1c3d3774d8a32b8ea0460330c16d1b2e3e5c0ea86ccc2d70e603aa8c8151d675dfe339d83f3f495fab226795789d4")[..]
    );

    let mut hmac = Hmac::<Sha384>::new_from_slice(b"again").expect("HMAC can take key of any size");
    hmac.update(b"hello");

    let result = hmac.finalize();
    assert_eq!(
        result.into_bytes()[..],
        hex!("4c549a549aa037e0fb651569bf271faa23cfa20e8a9d21438a6ff5bf6be916bebdbaa48001e0cd6941ec74cd02be70e5")[..]
    );
}
