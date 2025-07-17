use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_POINT,
};
use serde::{Deserialize, Serialize};

pub use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExecMode {
    Baseline,
    All,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

/// The `PublicKey` struct represents an ElGamal public key.
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct PublicKey(RistrettoPoint);

/// Secret key is a scalar forming the public Key.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretKey(Scalar);

#[derive(Serialize, Deserialize, Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    pub random_generator: RistrettoPoint,
    pub encrypted_plaintext: RistrettoPoint,
}

impl PublicKey {
    /// Create a new public key from a scalar.
    pub fn from(secret_key: &SecretKey) -> Self {
        PublicKey(secret_key.0 * RISTRETTO_BASEPOINT_POINT)
    }

    pub fn encrypt(&self, nonce: Scalar, message: &RistrettoPoint) -> Ciphertext {
        let random_generator = RISTRETTO_BASEPOINT_POINT * nonce;
        let encrypted_plaintext = message + self.0 * nonce;
        Ciphertext {
            random_generator,
            encrypted_plaintext,
        }
    }
}

impl SecretKey {
    pub fn new(scalar: Scalar) -> Self {
        SecretKey(scalar)
    }

    pub fn decrypt(&self, ciphertext: &Ciphertext) -> RistrettoPoint {
        ciphertext.encrypted_plaintext - ciphertext.random_generator * self.0
    }
}

