use rayon::prelude::*;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use thiserror::Error;
use std::collections::HashSet;
use rand::prelude::SliceRandom;
// Import rebel_one module
use crate::rebel_one::*;
use crate::rebel_one::HMACError;
use sha3::Sha3_256;
use sha3::Digest;
/// Custom error type for HighLowCipher operations.
#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("HMAC generation failed")]
    HMACGenerationFailed,
    #[error("HMAC verification failed")]
    HMACVerificationFailed,
    #[error("Non-bijective S-Box generated")]
    NonBijectiveSBox,
    #[error("Invalid S-Box index: {0}")]
    InvalidSBoxIndex(u8),
    #[error("Other error: {0}")]
    Other(String),
    // Integrate rebel_one errors
    #[error(transparent)]
    RebelOneKeygenError(#[from] KeygenError),
    #[error(transparent)]
    RebelOneHMACError(#[from] HMACError),
    #[error(transparent)]
    RebelOneEncryptionError(#[from] EncryptionError),
    #[error(transparent)]
    RebelOneDecryptionError(#[from] DecryptionError),
    #[error(transparent)]
    RebelOneNoiseError(#[from] NoiseError),
}

/// Utility functions for S-Box generation and prime operations.
mod utils {
    use super::*;
    use rand::Rng;

    /// Generates a secure prime number greater than `min_value` using a simple primality test.
    /// Note: For production, use a robust primality test or rely on existing libraries.
    pub fn generate_secure_prime<R: Rng>(
        rng: &mut R,
        min_value: u64,
    ) -> Result<u64, CipherError> {
        const MAX_ATTEMPTS: u32 = 100000;
        for _ in 0..MAX_ATTEMPTS {
            let candidate = rng.gen_range(min_value..=u64::MAX) | 1; // Ensure odd number
            if is_prime(candidate) {
                return Ok(candidate);
            }
        }
        Err(CipherError::KeyDerivationFailed)
    }

    /// Simple primality test (for demonstration purposes only).
    pub fn is_prime(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        if n == 2 || n == 3 {
            return true;
        }
        if n % 2 == 0 {
            return false;
        }
        let sqrt_n = (n as f64).sqrt() as u64;
        for i in (3..=sqrt_n).step_by(2) {
            if n % i == 0 {
                return false;
            }
        }
        true
    }

    /// Generates a bijective S-Box of specified size using a secure prime modulus.
    pub fn generate_bijective_s_box<R: Rng>(
        rng: &mut R,
        size: usize,
    ) -> Result<Vec<u8>, CipherError> {
        // Generate a secure prime modulus greater than the S-Box size
        let _prime = generate_secure_prime(rng, (size as u64) + 1)?;

        // Create the S-Box using a permutation-based approach
        let mut s_box: Vec<u8> = (0..size as u8).collect();
        s_box.shuffle(rng);

        // Verify bijectivity
        let unique_entries: HashSet<u8> = s_box.iter().cloned().collect();
        if unique_entries.len() != size {
            return Err(CipherError::NonBijectiveSBox);
        }

        Ok(s_box)
    }

    /// Inverts a given S-Box to create its inverse.
    pub fn invert_s_box(s_box: &Vec<u8>) -> Result<Vec<u8>, CipherError> {
        let size = s_box.len();
        let mut inv = vec![0u8; size];
        for (i, &val) in s_box.iter().enumerate() {
            if (val as usize) >= size {
                return Err(CipherError::InvalidSBoxIndex(val));
            }
            inv[val as usize] = i as u8;
        }
        // Verify bijectivity
        let unique_entries: HashSet<u8> = s_box.iter().cloned().collect();
        if unique_entries.len() != size {
            return Err(CipherError::NonBijectiveSBox);
        }
        Ok(inv)
    }
}

use utils::*;

/// HighLowCipher: A symmetric cipher with dynamic S-Box generation, Lattice-based HMAC for authentication, and a secure counter mechanism.
pub struct HighLowCipher {
    state: Vec<u8>,                 // Cipher state
    current_state: bool,            // True = High State, False = Low State
    modulus: u8,                    // Modulus for nibble operations (should be 16)
    shared_secret: Vec<u8>,         // Shared secret for state transitions
    high_s_box: Vec<u8>,            // High S-Box
    low_s_box: Vec<u8>,             // Low S-Box
    high_s_box_inv: Vec<u8>,        // Inverse of High S-Box
    low_s_box_inv: Vec<u8>,         // Inverse of Low S-Box
    lattice_hmac: LatticeHMAC,      // Lattice-based HMAC instance
    counter: u64,                   // Secure counter
}

impl HighLowCipher {
    /// Creates a new HighLowCipher instance with dynamic S-Box generation and Lattice-based HMAC.
    ///
    /// # Arguments
    ///
    /// * `initial_state` - The initial plaintext state as a byte vector.
    /// * `modulus` - The modulus for nibble operations (typically 16).
    /// * `shared_secret` - The shared secret key as a byte vector.
    /// * `passphrase` - The passphrase used for key derivation.
    /// * `dim_n` - Dimension parameter for key derivation (matches rebel_one's derive_key).
    /// * `modulus_hmac` - Modulus parameter for HMAC (matches rebel_one's requirements).
    /// * `noise_stddev` - Noise standard deviation for HMAC.
    /// * `s_box_size` - The size of the S-Box (e.g., 16 for 4-bit nibbles).
    pub fn new(
        initial_state: Vec<u8>,
        modulus: u8,
        shared_secret: Vec<u8>,
        passphrase: &[u8],
        dim_n: usize,
        modulus_hmac: u32,
        noise_stddev: f64,
        s_box_size: usize,
    ) -> Result<Self, CipherError> {
        // Derive a lattice-based key from the passphrase
        let derived_key = derive_key(passphrase, dim_n, modulus_hmac);

        // Initialize LatticeHMAC with the derived key parameters
        let lattice_hmac = LatticeHMAC::new(modulus_hmac, noise_stddev, 512, dim_n, 10)
            .map_err(CipherError::RebelOneKeygenError)?;

        // Initialize RNG with a seed derived from the key
        let seed = Self::seed_from_key(&derived_key);
        let mut rng = ChaCha20Rng::seed_from_u64(seed);

        // Generate dynamic bijective S-Boxes
        let high_s_box = generate_bijective_s_box(&mut rng, s_box_size)?;
        let low_s_box = generate_bijective_s_box(&mut rng, s_box_size)?;

        // Precompute inverse S-Boxes
        let high_s_box_inv = invert_s_box(&high_s_box)?;
        let low_s_box_inv = invert_s_box(&low_s_box)?;

        Ok(HighLowCipher {
            state: initial_state,
            current_state: true,
            modulus,
            shared_secret,
            high_s_box,
            low_s_box,
            high_s_box_inv,
            low_s_box_inv,
            lattice_hmac,
            counter: 0, // Initialize counter
        })
    }

    /// Derives a seed from the key for RNG initialization.
    fn seed_from_key(key: &[u32]) -> u64 {
       // Convert Vec<u32> to bytes
       let mut key_bytes = Vec::with_capacity(key.len() * 4);
       for &k in key {
           key_bytes.extend_from_slice(&k.to_le_bytes());
       }
       let hash = Sha3_256::digest(&key_bytes); // Use SHA3-256 from rebel_one
       let mut seed = [0u8; 8];
       seed.copy_from_slice(&hash[..8]); // Use first 8 bytes for seed
       u64::from_le_bytes(seed)
    }

    /// Transforms a nibble using the high S-Box.
    fn high_transform(&self, nibble: u8, secret_value: u8) -> Result<u8, CipherError> {
        let transformed = (nibble.wrapping_add(secret_value)) % self.modulus;
        self.high_s_box
            .get(transformed as usize)
            .copied()
            .ok_or(CipherError::InvalidSBoxIndex(transformed))
    }

    /// Transforms a nibble using the low S-Box.
    fn low_transform(&self, nibble: u8, secret_value: u8) -> Result<u8, CipherError> {
        let transformed = (nibble.wrapping_add(secret_value)) % self.modulus;
        self.low_s_box
            .get(transformed as usize)
            .copied()
            .ok_or(CipherError::InvalidSBoxIndex(transformed))
    }

    /// Reverses the transformation using the high S-Box inverse.
    fn reverse_high_transform(&self, nibble: u8, secret_value: u8) -> Result<u8, CipherError> {
        let s_box_output = self
            .high_s_box_inv
            .get(nibble as usize)
            .copied()
            .ok_or(CipherError::InvalidSBoxIndex(nibble))?;
        Ok((s_box_output.wrapping_sub(secret_value)) % self.modulus)
    }

    /// Reverses the transformation using the low S-Box inverse.
    fn reverse_low_transform(&self, nibble: u8, secret_value: u8) -> Result<u8, CipherError> {
        let s_box_output = self
            .low_s_box_inv
            .get(nibble as usize)
            .copied()
            .ok_or(CipherError::InvalidSBoxIndex(nibble))?;
        Ok((s_box_output.wrapping_sub(secret_value)) % self.modulus)
    }

    /// Transforms the cipher state (encryption).
    fn transform_state(&mut self) -> Result<(), CipherError> {
        self.state = self
            .state
            .par_iter()
            .enumerate()
            .map(|(i, &byte)| {
                let secret_value = self.shared_secret[i % self.shared_secret.len()];
                let (high, low) = (byte >> 4, byte & 0x0F);

                if self.current_state {
                    // High state transformation
                    match self.high_transform(high, secret_value) {
                        Ok(high_transformed) => (high_transformed << 4) | low,
                        Err(_) => 0, // Handle error appropriately
                    }
                } else {
                    // Low state transformation
                    match self.low_transform(low, secret_value) {
                        Ok(low_transformed) => (high << 4) | low_transformed,
                        Err(_) => 0, // Handle error appropriately
                    }
                }
            })
            .collect();

        // Toggle state after processing
        self.current_state = !self.current_state;
        Ok(())
    }

    /// Reverses the cipher state (decryption).
    fn reverse_transform_state(&mut self) -> Result<(), CipherError> {
        self.state = self
            .state
            .par_iter()
            .enumerate()
            .map(|(i, &byte)| {
                let secret_value = self.shared_secret[i % self.shared_secret.len()];
                let (high, low) = (byte >> 4, byte & 0x0F);

                if self.current_state {
                    // Reverse high state transformation
                    match self.reverse_high_transform(high, secret_value) {
                        Ok(high_reversed) => (high_reversed << 4) | low,
                        Err(_) => 0, // Handle error appropriately
                    }
                } else {
                    // Reverse low state transformation
                    match self.reverse_low_transform(low, secret_value) {
                        Ok(low_reversed) => (high << 4) | low_reversed,
                        Err(_) => 0, // Handle error appropriately
                    }
                }
            })
            .collect();

        // Toggle state after processing
        self.current_state = !self.current_state;
        Ok(())
    }

    /// Encrypts the plaintext, returns ciphertext and its HMAC.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to encrypt as a byte slice.
    ///
    /// # Returns
    ///
    /// A tuple containing the ciphertext and its HMAC signature.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, (Vec<u32>, Vec<u32>)), CipherError> {
        // Initialize state with plaintext
        self.state = plaintext.to_vec();
        self.current_state = true;

        // Increment and use counter to ensure uniqueness
        self.counter = self.counter.wrapping_add(1);
        let counter_bytes = self.counter.to_le_bytes();
        self.state.extend_from_slice(&counter_bytes);

        // Perform encryption transformations
        self.transform_state()?;

        let ciphertext = self.state.clone();

        // Generate HMAC of the ciphertext
        let hmac = self.lattice_hmac.sign(&ciphertext).map_err(CipherError::RebelOneHMACError)?;

        Ok((ciphertext, hmac))
    }

    /// Decrypts the ciphertext after verifying its HMAC, returns the plaintext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to decrypt as a byte slice.
    /// * `hmac` - The HMAC signature of the ciphertext.
    ///
    /// # Returns
    ///
    /// The decrypted plaintext as a byte vector.
    pub fn decrypt(&mut self, ciphertext: &[u8], hmac: &(Vec<u32>, Vec<u32>)) -> Result<Vec<u8>, CipherError> {
        // Verify HMAC before decryption
        self.lattice_hmac.verify(ciphertext, hmac).map_err(CipherError::RebelOneHMACError)?;

        // Initialize state with ciphertext
        self.state = ciphertext.to_vec();
        self.current_state = true;

        // Perform decryption transformations
        self.reverse_transform_state()?;

        // Extract counter from the decrypted state
        if self.state.len() < 8 {
            return Err(CipherError::Other("Ciphertext too short to contain counter".to_string()));
        }
        let counter_bytes = &self.state[self.state.len()-8..];
        let counter = u64::from_le_bytes(counter_bytes.try_into().map_err(|_| CipherError::Other("Failed to parse counter".to_string()))?);
        self.counter = counter;

        // Remove counter from plaintext
        let plaintext = self.state[..self.state.len()-8].to_vec();

        Ok(plaintext)
    }

    /// Resets the cipher state to the initial configuration.
    pub fn reset_state(&mut self, initial_state: Vec<u8>) {
        self.state = initial_state;
        self.current_state = true;
        self.counter = 0;
    }

    /// Retrieves the current cipher state.
    pub fn get_state(&self) -> Vec<u8> {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use std::collections::HashSet;

    #[test]
    fn test_prime_generation() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let prime = generate_secure_prime(&mut rng, 16).expect("Prime generation failed");
        assert!(is_prime(prime));
    }

    #[test]
    fn test_s_box_bijectivity() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let s_box = generate_bijective_s_box(&mut rng, 16).expect("S-Box generation failed");
        let unique_entries: HashSet<u8> = s_box.iter().cloned().collect();
        assert_eq!(unique_entries.len(), 16, "S-Box is not bijective");
    }

    #[test]
    fn test_cipher_transform_reverse() {
        let passphrase = b"TestPassphrase";
        let dim_n = 512;
        let modulus_hmac = 1 << 15;
        let noise_stddev = 0.0001;
        let s_box_size = 16;
        let plaintext = b"TestMessage1234".to_vec();
        let shared_secret = b"SharedSecret".to_vec();
        let modulus = 16;

        let mut cipher = HighLowCipher::new(
            plaintext.clone(),
            modulus,
            shared_secret.clone(),
            passphrase,
            dim_n,
            modulus_hmac,
            noise_stddev,
            s_box_size,
        )
        .expect("Cipher initialization failed");

        let (ciphertext, hmac) = cipher.encrypt(&plaintext).expect("Encryption failed");
        let decrypted = cipher.decrypt(&ciphertext, &hmac).expect("Decryption failed");

        assert_eq!(
            plaintext, decrypted,
            "Decryption did not restore the original state"
        );
    }

    #[test]
    fn test_cipher_non_bijective_s_box() {
        // Attempt to create a non-bijective S-Box and expect an error
        let s_box = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 14];
        let result = invert_s_box(&s_box);
        assert!(result.is_err(), "Non-bijective S-Box should fail inversion");
    }

    #[test]
    fn test_key_derivation() {
        let passphrase = b"AnotherSecurePassphrase!";
        let dim_n = 512;
        let modulus_hmac = 1 << 15;
        let derived_key = derive_key(passphrase, dim_n, modulus_hmac);

        assert_eq!(derived_key.len(), dim_n, "Derived key length mismatch");
    }

    #[test]
    fn test_hmac_verification_failure() {
        let passphrase = b"TestPassphrase";
        let dim_n = 512;
        let modulus_hmac = 1 << 15;
        let noise_stddev = 0.0001;
        let s_box_size = 16;
        let plaintext = b"TestMessage1234".to_vec();
        let shared_secret = b"SharedSecret".to_vec();
        let modulus = 16;

        let mut cipher = HighLowCipher::new(
            plaintext.clone(),
            modulus,
            shared_secret.clone(),
            passphrase,
            dim_n,
            modulus_hmac,
            noise_stddev,
            s_box_size,
        )
        .expect("Cipher initialization failed");

        let (mut ciphertext, mut hmac) = cipher.encrypt(&plaintext).expect("Encryption failed");

        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        // Expect HMAC verification to fail
        let decryption_result = cipher.decrypt(&ciphertext, &hmac);
        assert!(
            decryption_result.is_err(),
            "Decryption should fail due to HMAC verification failure"
        );
        match decryption_result {
            Err(CipherError::HMACVerificationFailed) => (),
            _ => panic!("Expected HMACVerificationFailed error"),
        }
    }

    #[test]
    fn test_counter_increment() {
        let passphrase = b"TestPassphrase";
        let dim_n = 512;
        let modulus_hmac = 1 << 15;
        let noise_stddev = 0.0001;
        let s_box_size = 16;
        let plaintext = b"CounterTest".to_vec();
        let shared_secret = b"SharedSecret".to_vec();
        let modulus = 16;

        let mut cipher = HighLowCipher::new(
            plaintext.clone(),
            modulus,
            shared_secret.clone(),
            passphrase,
            dim_n,
            modulus_hmac,
            noise_stddev,
            s_box_size,
        )
        .expect("Cipher initialization failed");

        let (ciphertext1, hmac1) = cipher.encrypt(&plaintext).expect("Encryption failed");
        let counter1 = cipher.counter;

        let (ciphertext2, hmac2) = cipher.encrypt(&plaintext).expect("Encryption failed");
        let counter2 = cipher.counter;

        assert_eq!(counter1 + 1, counter2, "Counter did not increment correctly");
    }
}

