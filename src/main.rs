mod rebel_one;
mod high_low_cipher;
use rand::Rng;
use crate::high_low_cipher::HighLowCipher;
use crate::high_low_cipher::CipherError;
use hex::encode;
use std::io::{self, Write};
fn generate_dynamic_inputs(plaintext: Vec<u8>) -> (Vec<u8>, Vec<u8>, u8, usize, usize) {
    let mut rng = rand::thread_rng();

    // Generate a random passphrase
    let passphrase: Vec<u8> = (0..16).map(|_| rng.gen_range(b'a'..=b'z')).collect();

    // Generate a random shared secret
    let shared_secret: Vec<u8> = (0..16).map(|_| rng.gen_range(0..=255)).collect();

    // Set a modulus dynamically
    let modulus: u8 = 16; // Default modulus, adjustable if needed

    // Define an S-Box size
    let s_box_size: usize = 16; // Default S-Box size, configurable as needed

    // Set the dimension parameter for key derivation
    let dim_n: usize = 512; // Default dimension parameter, could be adjusted dynamically

    (passphrase, shared_secret, modulus, s_box_size, dim_n)
}

fn vec_u32_to_bytes(vec: &Vec<u32>) -> Vec<u8> {
    vec.iter()
        .flat_map(|x| x.to_le_bytes()) // Convert each u32 to 4 bytes in little-endian order
        .collect()
}

fn main() -> Result<(), CipherError> {
    // Function to get user input
    fn get_input(prompt: &str) -> String {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    }

    // Get inputs dynamically from the user
     let plaintext = get_input("Enter plaintext to encrypt: ").into_bytes();

    // Generate the other inputs dynamically
    let (passphrase, shared_secret, modulus, s_box_size, dim_n) = generate_dynamic_inputs(plaintext.clone());

    // Output generated values for debugging or logging purposes
    println!("User Input Plaintext: {:?}", String::from_utf8(plaintext.clone()).unwrap());
    println!("Generated Passphrase: {:?}", String::from_utf8(passphrase.clone()).unwrap());
    println!("Generated Shared Secret: {:?}", shared_secret);
    println!("Modulus: {}", modulus);
    println!("S-Box Size: {}", s_box_size);
    println!("Dimension Parameter (dim_n): {}", dim_n);

    let modulus_hmac: u32 = 1 << 15; // Can be adjusted based on input needs
    let noise_stddev: f64 = get_input("Enter noise standard deviation (e.g., 0.1): ")
        .parse()
        .unwrap_or(0.1);

    // Create a new HighLowCipher instance with dynamic S-Boxes and Lattice-based HMAC
    let mut cipher = HighLowCipher::new(
        plaintext.clone(),
        modulus, // Corrected to `u8`
        shared_secret,
        &passphrase,
        dim_n,
        modulus_hmac,
        noise_stddev,
        s_box_size,
    )?;

    // Encrypt the plaintext
    let (ciphertext, hmac) = cipher.encrypt(&plaintext)?;
    println!("Ciphertext (Hex): {}", encode(&ciphertext));
    println!(
        "HMAC (Hex): (Hash: {}, Metadata: {})",
        encode(vec_u32_to_bytes(&hmac.0)),
        encode(vec_u32_to_bytes(&hmac.1))
    );

    // Decrypt the ciphertext
    let decrypted = cipher.decrypt(&ciphertext, &hmac)?;
    println!(
        "Decrypted: {}",
        String::from_utf8_lossy(&decrypted)
    );

    // Verify that the decrypted plaintext matches the original
    assert_eq!(
        plaintext, decrypted,
        "Decryption failed: Original plaintext and decrypted text do not match"
    );

    println!("Encryption and decryption successful with Lattice-based HMAC verification!");
    Ok(())
}

