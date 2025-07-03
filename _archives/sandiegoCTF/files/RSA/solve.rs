use std::convert::TryInto;

// Konstanta RSA (prime kecil untuk demo, TIDAK aman secara kriptografi)
const P: u128 = 32416190071;
const Q: u128 = 32416187567;
const N: u128 = P * Q;
const PHI: u128 = (P - 1) * (Q - 1);
const E: u128 = 65537;
const D: u128 = modinv(E, PHI).expect("Modular inverse tidak ditemukan!");

// Fungsi modular exponentiation: x^y mod n
fn mod_exp(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    let mut result = 1;
    base %= modulus;
    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exp /= 2;
    }
    result
}

// Euclidean Algorithm Extended untuk modular inverse
fn modinv(a: u128, m: u128) -> Option<u128> {
    let (mut t, mut new_t) = (0, 1);
    let (mut r, mut new_r) = (m, a);

    while new_r != 0 {
        let quotient = r / new_r;
        t = t - quotient * new_t;
        std::mem::swap(&mut t, &mut new_t);
        r = r - quotient * new_r;
        std::mem::swap(&mut r, &mut new_r);
    }

    if r > 1 {
        return None;
    }
    if t < 0 {
        t += m as i128;
    }
    Some(t as u128)
}

// String -> u128
fn str_to_u128(s: &str) -> u128 {
    let bytes = s.as_bytes();
    u128::from_be_bytes(bytes.try_into().expect("Must be 16 characters"))
}

// u128 -> String
fn u128_to_str(n: u128) -> String {
    let bytes = n.to_be_bytes();
    String::from_utf8_lossy(&bytes).to_string()
}

fn main() {
    let plaintext = "abcdefghijklmnop";
    println!("Plaintext: {}", plaintext);

    // Encode
    let m = str_to_u128(plaintext);
    let c = mod_exp(m, E, N);
    println!("Ciphertext: {}", c);

    // Decode
    let m_dec = mod_exp(c, D, N);
    let decrypted = u128_to_str(m_dec);
    println!("Decrypted: {}", decrypted);
}
