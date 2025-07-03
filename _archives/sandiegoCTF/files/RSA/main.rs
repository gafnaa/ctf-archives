use std::io;
use std::convert::TryInto;

const PUBLIC_EXP: u128 = 65537;

// computes x^y mod n
fn mod_exp(x: u128, y: u128) -> u128 {
    let mut bit_length:u128 = 0;
    let mut y0:u128 = y;
    while y0 > 0 {
        y0 >>= 1;
        bit_length += 1;
    }
    let mut result:u128 = 1;
    for i in (0..bit_length).rev() {
        result = result * result;
        if (y >> i) & 1 == 1 {
            result = result * x;
        }
    }
    return result;
}

fn main() {
    let stdin = io::stdin();
    let plaintext = &mut String::new();
    println!("RustSA encryption service! Type your message below (exactly 16 characters):");
    let _ = stdin.read_line(plaintext);
    let plaintext_bytes_untrimmed = plaintext.as_bytes();
    let plaintext_bytes = &plaintext_bytes_untrimmed[0..plaintext_bytes_untrimmed.len()-1];
    if plaintext_bytes.len() != 16 {
        println!("Message not 16 characters.");
        return;
    }
    let plaintext_int = u128::from_be_bytes(plaintext_bytes.try_into().expect("Conversion Error"));
    let result = mod_exp(plaintext_int, PUBLIC_EXP);
    println!("Your ciphertext is below:");
    println!("{}", result);
}