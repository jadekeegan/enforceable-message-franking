use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::rngs::OsRng;

pub type Ciphertext = (RistrettoPoint, RistrettoPoint);

// Elgamal Keygen
/// Generate an ElGamal key pair.
///
/// # Returns
/// * `(sk, pk)` - Secret key and public key
pub fn elgamal_keygen() -> (Scalar, RistrettoPoint) {
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
pub fn encrypt_point(pk: &RistrettoPoint, point: &RistrettoPoint) -> Ciphertext {
    let r = Scalar::random(&mut OsRng);

    // c1 = g^r
    let c1 = RistrettoPoint::mul_base(&r);

    // c2 = pk^r + point
    let c2 = r * pk + point;
    (c1, c2)
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
pub fn decrypt_point(sk: &Scalar, ct: &Ciphertext) -> RistrettoPoint {
    ct.1 - sk * ct.0
}
