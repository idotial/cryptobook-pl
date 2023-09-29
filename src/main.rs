mod hash;
mod mac;

fn main() {
    println!("hash section: ");
    hash::test();
    println!("mac section: ");
    mac::test();
}
