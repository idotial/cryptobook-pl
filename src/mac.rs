use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use hex_literal::hex;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};
use scrypt::{scrypt, Params};
use sha2::{Sha256, Sha384};

pub fn test() {
    println!("test with hmac");
    let mut hmac = Hmac::<Sha256>::new_from_slice(b"key").expect("HMAC can take key of any size");
    hmac.update(b"some msg");

    let result = hmac.finalize();

    println!("{:x?}", hex::encode(result.into_bytes()));

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

    println!("test with kdf");
    let password = b"p@$Sw0rD~1";
    let salt = hex::decode("aaef2d3f4d77ac66e9c5a6c3d8f921d1").unwrap();
    // number of iterations
    let n = 50000;
    // Expected value of generated key
    let expected = hex!("52c5efa16e7022859051b1dec28bc65d9696a3005d0f97e506c42843bc3bdbc0");

    let mut key1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, &salt, n, &mut key1);
    assert_eq!(key1, expected);

    let key2 = pbkdf2_hmac_array::<Sha256, 32>(password, &salt, n);
    assert_eq!(key2, expected);
    println!("Scrypt: ");

    let mut result = vec![0u8; 32];
    let params = Params::new(11, 8, 1, 32).unwrap();
    scrypt(
        b"p@$Sw0rD~7",
        &hex::decode("aa1f2d3f4d23ac44e9c5a6c3d8f9ee8c").unwrap(),
        &params,
        &mut result,
    )
    .unwrap();
    println!("Derived key?: {}", hex::encode(result));

    let password = b"hunter42"; // Bad password; don't actually use!
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2.hash_password(password, &salt).unwrap().to_string();

    // Verify password against PHC string.
    //
    // NOTE: hash params from `parsed_hash` are used instead of what is configured in the
    // `Argon2` instance.
    let parsed_hash = PasswordHash::new(&password_hash).unwrap();
    assert!(Argon2::default()
        .verify_password(password, &parsed_hash)
        .is_ok());
}
