#![no_main]
sp1_zkvm::entrypoint!(main);

use jwt_rustcrypto::{decode, Algorithm, ValidationOptions, VerifyingKey};
use lib::split_email;

pub fn main() {
    let token = sp1_zkvm::io::read::<String>();
    let rsa_public_key = sp1_zkvm::io::read::<String>();
    let domain = sp1_zkvm::io::read::<String>();

    sp1_zkvm::io::commit(&domain);

    let validation_options = ValidationOptions::default()
        .with_algorithm(Algorithm::RS256)
        .without_expiry();

    let verification_key = VerifyingKey::from_rsa_pem(rsa_public_key.as_bytes())
        .expect("Failed to create verifying key from RSA public key");

    let decoded = decode(&token, &verification_key, &validation_options)
        .expect("Failed to decode or validate JWT with RSA key");

    let email_parts = split_email(decoded.payload.get("email").unwrap().to_string()).unwrap();

    let verified = email_parts.domain == domain;
    sp1_zkvm::io::commit(&verified);
}
