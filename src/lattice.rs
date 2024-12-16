use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_distr::{Distribution, Normal};
use thiserror::Error;

/// Custom error type for noise addition
#[derive(Error, Debug)]
pub enum NoiseError {
    #[error("Invalid standard deviation")]
    InvalidStdDev,
}

/// Custom error type for key generation
#[derive(Error, Debug)]
pub enum KeygenError {
    #[error("Noise addition failed")]
    NoiseAdditionFailed,
}

/// Custom error type for encryption
#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Noise addition failed")]
    NoiseAdditionFailed,
}

/// Custom error type for decryption
#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("Ciphertext and secret vector dimensions do not match")]
    InvalidDimensions,
}

/// Adds Gaussian noise to a value, simulating the "error" in LWE
fn add_gaussian_noise<R: Rng>(
    rng: &mut R,
    value: u32,
    modulus: u32,
    stddev: f64,
) -> Result<u32, NoiseError> {
    let normal = Normal::new(0.0, stddev).map_err(|_| NoiseError::InvalidStdDev)?;
    let noise: i32 = normal.sample(rng).round() as i32;

    Ok(((value as i32 + noise + modulus as i32) % modulus as i32) as u32)
}

/// Key generation for lattice-based cryptography
/// Generates public and private key pairs along with error (noise)
pub fn keygen(
    dim_m: usize,
    dim_n: usize,
    modulus: u32,
    noise_stddev: f64,
    rng: &mut ChaCha20Rng,
) -> Result<(Vec<Vec<u32>>, Vec<u32>, Vec<u32>), KeygenError> {
    // Generate a random matrix A (dim_m x dim_n)
    let a: Vec<Vec<u32>> = (0..dim_m)
        .map(|_| (0..dim_n).map(|_| rng.gen_range(0..modulus)).collect())
        .collect();

    // Generate a random secret vector s (dim_n)
    let s: Vec<u32> = (0..dim_n).map(|_| rng.gen_range(0..modulus)).collect();

    // Compute b = A * s + noise
    let b: Vec<u32> = a
        .iter()
        .map(|row| {
            let dot_product: u32 = row
                .iter()
                .zip(&s)
                .map(|(ai, si)| ai.wrapping_mul(*si))
                .sum::<u32>()
                % modulus;
            add_gaussian_noise(rng, dot_product, modulus, noise_stddev)
                .map_err(|_| KeygenError::NoiseAdditionFailed)
        })
        .collect::<Result<Vec<u32>, KeygenError>>()?;

    Ok((a, b, s)) // Return the public key (A, b) and private key (s)
}

/// Computes a shared secret given a public key (A, b) and a private key (s)
pub fn compute_shared_secret(
    public_key: &(Vec<Vec<u32>>, Vec<u32>),
    secret: &Vec<u32>,
    modulus: u32,
) -> Vec<u32> {
    let (a, b) = public_key;

    // Compute A * s mod modulus
    let a_s: Vec<u32> = a
        .iter()
        .map(|row| {
            row.iter()
                .zip(secret.iter())
                .map(|(ai, si)| ai.wrapping_mul(*si))
                .sum::<u32>()
                % modulus
        })
        .collect();

    a_s
}

/// Encrypts an array of bits (0 or 1) using a public key (A, b)
pub fn encrypt_multi_bits<R: Rng>(
    bits: &[bool], // Array of bits represented as bools
    public_key: &(Vec<Vec<u32>>, Vec<u32>),
    modulus: u32,
    noise_stddev: f64,
    rng: &mut R,
) -> Result<(Vec<u32>, Vec<u32>), EncryptionError> {
    let (a, b) = public_key;
    let dim_m = a.len();
    let dim_n = if dim_m > 0 { a[0].len() } else { 0 };

    // Generate a random vector r of length dim_n
    let r: Vec<u32> = (0..dim_n).map(|_| rng.gen_range(0..modulus)).collect();

    // Compute u = A * r mod modulus
    let u: Vec<u32> = a
        .iter()
        .map(|row| {
            row.iter()
                .zip(&r)
                .map(|(ai, ri)| ai.wrapping_mul(*ri))
                .sum::<u32>()
                % modulus
        })
        .collect();

    // Compute b * r mod modulus once
    let b_r: u32 = b
        .iter()
        .zip(&r)
        .map(|(bi, ri)| bi.wrapping_mul(*ri))
        .sum::<u32>()
        % modulus;

    // Compute v for each bit
    let mut v = Vec::with_capacity(bits.len());
    for &bit in bits {
        let mut vi = b_r;
        vi = add_gaussian_noise(rng, vi, modulus, noise_stddev)?
            .wrapping_add(bit as u32 * (modulus / 2))
            % modulus;
        v.push(vi);
    }

    Ok((u, v))
}

/// Decrypts the ciphertext using a private key (s)
pub fn decrypt_multi_bits(
    ciphertext: &(Vec<u32>, Vec<u32>),
    secret: &Vec<u32>,
    modulus: u32,
) -> Result<Vec<u32>, DecryptionError> {
    let (u, v) = ciphertext;

    // Ensure that the lengths of u and secret match
    if u.len() != secret.len() {
        return Err(DecryptionError::InvalidDimensions);
    }

    let mut decrypted_bits = Vec::with_capacity(v.len());

    for &vi in v {
        // Compute A * s mod q
        let dot_product: u32 = u
            .iter()
            .zip(secret.iter())
            .map(|(ui, si)| ui.wrapping_mul(*si))
            .sum::<u32>()
            % modulus;

        // Compute decoded_value = (vi - dot_product) mod q
        let decoded_value = (vi + modulus - dot_product) % modulus;

        // Determine if the decoded value corresponds to 0 or 1
        if decoded_value > modulus / 4 && decoded_value < 3 * modulus / 4 {

