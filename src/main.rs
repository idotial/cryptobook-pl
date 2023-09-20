use blake2::{Blake2b512, Blake2s256, Digest as Blake2_Digest};
use ripemd::{Digest, Ripemd160, Ripemd320};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use sha3::{Keccak256, Sha3_256};

fn main() {
    // create a SHA3-256 object
    let mut sha3_hasher = Sha3_256::new();
    // write input message
    Update::update(&mut sha3_hasher, b"hello");
    // read hash digest
    let result = sha3_hasher.finalize();
    println!("{:x?}", hex::encode(result));

    // SHAKE functions have an extendable output, so finalization method returns XOF reader from which results of arbitrary length can be read. Note that these functions do not implement Digest, so lower-level traits have to be imported
    let mut shake_hasher = Shake128::default();
    shake_hasher.update(b"hello");
    let mut reader = shake_hasher.finalize_xof();
    let mut res1 = [0u8; 32];
    reader.read(&mut res1);
    println!("{:x?}", hex::encode(res1));

    // keccak 256
    let mut keccak_hasher = Keccak256::new();
    Update::update(&mut keccak_hasher, b"hello");
    let result = keccak_hasher.finalize();
    println!("{:x?}", hex::encode(result));

    // blake2
    let mut hasher = Blake2s256::new();
    Blake2_Digest::update(&mut hasher, b"hello");
    let result = hasher.finalize();
    println!("{:x?}", hex::encode(result));

    let mut hasher = Blake2b512::new();
    Blake2_Digest::update(&mut hasher, b"hello");
    let result = hasher.finalize();
    println!("{:x?}", hex::encode(result));

    // RIPEMD-160
    let mut hasher = Ripemd160::new();
    Digest::update(&mut hasher, b"hello");
    let result = hasher.finalize();
    println!("{:x?}", hex::encode(result));
    // RIPEMD-320
    let mut hasher = Ripemd320::new();
    Digest::update(&mut hasher, b"hello");
    let result = hasher.finalize();
    println!("{:x?}", hex::encode(result));
}
