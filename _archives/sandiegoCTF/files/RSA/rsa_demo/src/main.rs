use std::convert::TryInto;

// Konstanta yang aman
const P: u128 = 32416190071;
const Q: u128 = 32416187567;
const E: u128 = 65537;

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

fn modinv(a: u128, m: u128) -> Option<u128> {
    let (mut t, mut new_t): (i128, i128) = (0, 1);
    let (mut r, mut new_r): (i128, i128) = (m as i128, a as i128);

    while new_r != 0 {
        let quotient = r / new_r;
        let temp_t = t - quotient * new_t;
        t = new_t;
        new_t = temp_t;

        let temp_r = r - quotient * new_r;
        r = new_r;
        new_r = temp_r;
    }

    if r > 1 {
        return None;
    }
    if t < 0 {
        t += m as i128;
    }
    Some(t as u128)
}

fn str_to_u128(s: &str) -> u128 {
    let bytes = s.as_bytes();
    u128::from_be_bytes(bytes.try_into().expect("Harus 16 karakter"))
}

fn u128_to_str(n: u128) -> String {
    let bytes = n.to_be_bytes();
    String::from_utf8_lossy(&bytes).to_string()
}

fn main() {
    // ⬇️ Dipindah dari `const` ke `let`
    let n = P * Q;
    let phi = (P - 1) * (Q - 1);
    let d = modinv(E, phi).expect("Tidak bisa cari modular inverse");

    let plaintext = "abcdefghijklmnop";
    println!("Plaintext: {}", plaintext);

    let m = str_to_u128(plaintext);
    let c = mod_exp(m, E, n);
    println!("Ciphertext: {}", c);

    let m_dec = mod_exp(c, d, n);
    let decrypted = u128_to_str(m_dec);
    println!("Decrypted: {}", decrypted);
}
