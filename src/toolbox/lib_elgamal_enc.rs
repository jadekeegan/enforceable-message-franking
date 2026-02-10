use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use rand::rngs::OsRng;

// Type Definitions
pub type ElGamalCiphertext = (CompressedRistretto, CompressedRistretto);
pub type ElGamalSecretKey = Scalar;
pub type ElGamalPublicKey = RistrettoPoint;

// Elgamal Keygen
/// Generate an ElGamal key pair.
///
/// # Returns
/// * `(sk, pk)` - Secret key and public key
pub fn keygen() -> (ElGamalSecretKey, ElGamalPublicKey) {
    let sk = Scalar::random(&mut OsRng);
    let pk = RistrettoPoint::mul_base(&sk);
    (sk, pk)
}

// Elgamal Encryption
/// Encrypt a RistrettoPoint using ElGamal encryption.
///
/// # Arguments
/// * `pk` - Public key
/// * `point` - Point to encrypt
///
/// # Returns
/// * `(c1, c2)` - ElGamal ciphertext
/// * `r` - Random scalar used in encryption
pub fn encrypt(pk: &ElGamalPublicKey, point: &CompressedRistretto) -> (ElGamalCiphertext, Scalar) {
    let r = Scalar::random(&mut OsRng);

    // c1 = g^r
    let c1 = RistrettoPoint::mul_base(&r);

    // c2 = pk^r + point
    let c2 = r * pk + point.decompress().unwrap();
    ((c1.compress(), c2.compress()), r)
}

// Elgamal Decryption
/// Decrypt an ElGamal ciphertext to recover the encrypted point.
///
/// # Arguments
/// * `sk` - Secret key
/// * `ct` - Ciphertext (c1, c2)
///
/// # Returns
/// * Decrypted RistrettoPoint
pub fn decrypt(sk: &ElGamalSecretKey, ct: &ElGamalCiphertext) -> CompressedRistretto {
    let tag = ct.1.decompress().unwrap() - sk * ct.0.decompress().unwrap();
    tag.compress()
}
