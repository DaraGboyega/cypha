pub mod cipher;

extern crate hex;

fn main() {
    let text = cipher::decrypt_aes_ecb("cryptopals-7.txt", "YELLOW SUBMARINE");
    println!("decoded: {:?}", text);
}
