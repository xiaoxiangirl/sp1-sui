#![no_main]
sp1_zkvm::entrypoint!(main);

use lib::{split_email, split_jwt, pem_to_der};
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256};

pub fn main() {
    let token = sp1_zkvm::io::read::<String>();
    let rsa_public_key = sp1_zkvm::io::read::<String>();
    let domain = sp1_zkvm::io::read::<String>();

    sp1_zkvm::io::commit(&domain);

    let (payload, signature) = split_jwt(&token)
        .expect("Failed to decode JWT");
    
    let pk_der = pem_to_der(&rsa_public_key);
    let public_key = RsaPublicKey::from_public_key_der(&pk_der).unwrap();

    let signing_input = format!(
        "{}.{}",
        token.split('.').collect::<Vec<&str>>()[0],
        token.split('.').collect::<Vec<&str>>()[1]
    );
    let mut hasher = Sha256::new();
    hasher.update(signing_input);
    let hashed_msg = hasher.finalize();

    let _verification = public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_msg, &signature);
    //sp1_zkvm::io::commit(&verification);

    let email_parts = split_email(payload.get("email").unwrap().to_string()).unwrap();
    let verified = email_parts.domain == domain;
    sp1_zkvm::io::commit(&verified);
}

