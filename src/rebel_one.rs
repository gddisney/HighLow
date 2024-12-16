// src/rebel_one.rs

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_distr::{Distribution, Normal};
use sha3::{Digest, Sha3_256, Shake256};
use sha3::digest::{Update, ExtendableOutput, XofReader};
use thiserror::Error;
use std::io::Read;

/// --- Noise Error ---
#[derive(Error, Debug)]
pub enum NoiseError {
    #[error("Invalid standard deviation")]
    InvalidStdDev,
}

/// --- Key Generation Error ---
#[derive(Error, Debug)]
pub enum KeygenError {
    #[error("Noise addition failed")]
    NoiseAdditionFailed,
}

/// --- Encryption Error ---
#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Noise addition failed")]
    NoiseAdditionFailed,
    #[error(transparent)]
    Noise(#[from] NoiseError),
}

/// --- Decryption Error ---
#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("Ciphertext and secret vector dimensions do not match")]
    InvalidDimensions,
}

/// --- HMAC Error ---
#[derive(Error, Debug)]
pub enum HMACError {
    #[error("Signature generation failed")]
    SignError,
    #[error("Signature verification failed")]
    VerifyError,
}

/// Adds Gaussian noise to a value, simulating the "error" in LWE
pub fn add_gaussian_noise<R: Rng>(
    rng: &mut R,
    value: u32,
    modulus: u32,
    stddev: f64,
) -> Result<u32, NoiseError> {
    let normal = Normal::new(0.0, stddev).map_err(|_| NoiseError::InvalidStdDev)?;
    let noise: i32 = normal.sample(rng).round() as i32;

    Ok(((value as i32 + noise + modulus as i32) % modulus as i32) as u32)
}

/// Key generation for lattice-based cryptography with retry mechanism
pub fn keygen(
    dim_m: usize,
    dim_n: usize,
    modulus: u32,
    noise_stddev: f64,
    rng: &mut ChaCha20Rng,
    max_retries: usize,
) -> Result<(Vec<Vec<u32>>, Vec<u32>, Vec<u32>), KeygenError> {
    assert!(dim_m > 0, "dim_m must be greater than zero.");
    assert!(dim_n > 0, "dim_n must be greater than zero.");
    assert!(modulus > 0, "Modulus must be greater than zero.");
    assert!(noise_stddev > 0.0, "Noise standard deviation must be positive.");

    for attempt in 0..=max_retries {
        let a: Vec<Vec<u32>> = (0..dim_m)
            .map(|_| (0..dim_n).map(|_| rng.gen_range(0..modulus)).collect())
            .collect();

        if a.is_empty() || a[0].len() != dim_n {
            if attempt == max_retries {
                return Err(KeygenError::NoiseAdditionFailed);
            }
            continue;
        }

        let s: Vec<u32> = (0..dim_n).map(|_| rng.gen_range(0..modulus)).collect();

        let b_result: Result<Vec<u32>, KeygenError> = a
            .iter()
            .map(|row| {
                let dot_product: u64 = row
                    .iter()
                    .zip(&s)
                    .map(|(ai, si)| (*ai as u64) * (*si as u64))
                    .sum();

                let dot_product_mod = (dot_product % (modulus as u64)) as u32;

                add_gaussian_noise(rng, dot_product_mod, modulus, noise_stddev)
                    .map_err(|_| KeygenError::NoiseAdditionFailed)
            })
            .collect();

        match b_result {
            Ok(b) => return Ok((a, b, s)),
            Err(_) => {
                if attempt == max_retries {
                    return Err(KeygenError::NoiseAdditionFailed);
                }
                continue;
            }
        }
    }

    Err(KeygenError::NoiseAdditionFailed)
}

/// Encrypts an array of bits (0 or 1) using a public key (A, b)
pub fn encrypt_multi_bits<R: Rng>(
    bits: &[bool],
    public_key: &(Vec<Vec<u32>>, Vec<u32>),
    modulus: u32,
    noise_stddev: f64,
    rng: &mut R,
) -> Result<(Vec<u32>, Vec<u32>), EncryptionError> {
    assert!(modulus > 0, "Modulus must be greater than zero.");
    assert!(!bits.is_empty(), "Input bits for encryption must not be empty.");

    let (a, b) = public_key;
    let dim_n = if !a.is_empty() { a[0].len() } else { 0 };

    assert!(!a.is_empty() && dim_n > 0, "Public key matrix A must not be empty.");
    assert!(b.len() == a.len(), "Public key vector B must match the number of rows in A.");

    let r: Vec<u32> = (0..dim_n).map(|_| rng.gen_range(0..modulus)).collect();

    let u: Vec<u32> = a
        .iter()
        .map(|row| {
            row.iter()
                .zip(&r)
                .map(|(ai, ri)| (*ai as u64 * *ri as u64) % modulus as u64)
                .sum::<u64>() as u32
                % modulus
        })
        .collect();

    let b_r: u32 = b
        .iter()
        .zip(&r)
        .map(|(bi, ri)| (*bi as u64 * *ri as u64) % modulus as u64)
        .sum::<u64>() as u32
        % modulus;

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

    if u.len() != secret.len() {
        return Err(DecryptionError::InvalidDimensions);
    }

    let mut decrypted_bits = Vec::with_capacity(v.len());
    for &vi in v {
        let dot_product: u64 = u
            .iter()
            .zip(secret.iter())
            .map(|(ui, si)| (*ui as u64) * (*si as u64))
            .sum();

        let dot_product_mod = (dot_product % (modulus as u64)) as u32;

        let decoded_value = (vi + modulus - dot_product_mod) % modulus;

        if decoded_value > modulus / 4 && decoded_value < 3 * modulus / 4 {
            decrypted_bits.push(1);
        } else {
            decrypted_bits.push(0);
        }
    }

    Ok(decrypted_bits)
}

/// Derives a lattice-based key from a passphrase
pub fn derive_key(passphrase: &[u8], dim_n: usize, modulus: u32) -> Vec<u32> {
    assert!(modulus > 0, "Modulus must be greater than zero.");
    assert!(dim_n > 0, "dim_n must be greater than zero.");

    let mut shake = Shake256::default();
    shake.update(passphrase);
    let mut reader = shake.finalize_xof();

    let mut key = Vec::with_capacity(dim_n);

    for _ in 0..dim_n {
        let mut buffer = [0u8; 4];
        reader.read_exact(&mut buffer).expect("Failed to read from XOF");
        let value = u32::from_le_bytes(buffer) % modulus;
        key.push(value);
    }

    key
}

/// Lattice-based HMAC context
pub struct LatticeHMAC {
    public_key: (Vec<Vec<u32>>, Vec<u32>),
    secret_key: Vec<u32>,
    modulus: u32,
    noise_stddev: f64,
}

impl LatticeHMAC {
    pub fn new(
        modulus: u32,
        noise_stddev: f64,
        dim_m: usize,
        dim_n: usize,
        max_retries: usize,
    ) -> Result<Self, KeygenError> {
        let mut rng = ChaCha20Rng::from_entropy();

        let (a, b, s) = keygen(dim_m, dim_n, modulus, noise_stddev, &mut rng, max_retries)?;

        Ok(Self {
            public_key: (a, b),
            secret_key: s,
            modulus,
            noise_stddev,
        })
    }

    pub fn sign(&self, data: &[u8]) -> Result<(Vec<u32>, Vec<u32>), HMACError> {
        assert!(!data.is_empty(), "Data to sign must not be empty.");

        let mut hasher = Shake256::default();
        hasher.update(data);

        let mut hash_output = [0u8; 64];
        hasher
            .finalize_xof()
            .read_exact(&mut hash_output)
            .map_err(|_| HMACError::SignError)?;

        let bits: Vec<bool> = hash_output
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 != 0))
            .collect();

        let mut rng = ChaCha20Rng::from_entropy();
        encrypt_multi_bits(
            &bits,
            &self.public_key,
            self.modulus,
            self.noise_stddev,
            &mut rng,
        )
        .map_err(|_| HMACError::SignError)
    }

    pub fn verify(&self, data: &[u8], signature: &(Vec<u32>, Vec<u32>)) -> Result<bool, HMACError> {
        let mut hasher = Shake256::default();
        hasher.update(data);

        let mut hash_output = [0u8; 64];
        hasher
            .finalize_xof()
            .read_exact(&mut hash_output)
            .map_err(|_| HMACError::VerifyError)?;

        let bits: Vec<bool> = hash_output
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 != 0))
            .collect();

        let decrypted_bits =
            decrypt_multi_bits(signature, &self.secret_key, self.modulus).map_err(|_| HMACError::VerifyError)?;

        let decrypted_bits_bool: Vec<bool> = decrypted_bits.iter().map(|&b| b != 0).collect();

        Ok(bits == decrypted_bits_bool)
    }
}

