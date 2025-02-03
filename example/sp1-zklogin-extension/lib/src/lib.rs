// Custom structs with seralize/deserialize.
use anyhow::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use base64::{engine::general_purpose, Engine as _};
use std::str::FromStr;
use blake2::{Blake2b, Digest, digest::consts::U32};
use hex_literal::hex;

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailParts {
    pub username: String,
    pub domain: String,
}


pub fn Blake2b256(inp: &str) -> Vec<u8> {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(inp.as_bytes());
    hasher.finalize().to_vec()
}

/// Calculate the Sui address based on address seed and address params.
/// taken from https://github.com/MystenLabs/fastcrypto/blob/0acf0ff1a163c60e0dec1e16e4fbad4a4cf853bd/fastcrypto-zkp/src/bn254/utils.rs#L26-L65
// pub fn get_zk_login_address(
//     address_seed: &Bn254FrElement,
//     iss: &str,
// ) -> [u8; 32] {
//     let mut hasher = Blake2b256::<U32>::new();
//     hasher.update([ZK_LOGIN_AUTHENTICATOR_FLAG]);
//     let bytes = iss.as_bytes();
//     hasher.update([bytes.len() as u8]);
//     hasher.update(bytes);
//     hasher.update(address_seed.padded());
//     Ok(hasher.finalize().to_vec())
// }

// /// Calculate the Sui address based on address seed and address params.
// pub fn gen_address_seed(
//     salt: &str,
//     name: &str,  // i.e. "sub"
//     value: &str, // i.e. the sub value
//     aud: &str,   // i.e. the client ID
// ) -> Result<String, FastCryptoError> {
//     let salt_hash = poseidon_zk_login(&[(&Bn254FrElement::from_str(salt)?).into()])?;
//     gen_address_seed_with_salt_hash(&salt_hash.to_string(), name, value, aud)
// }

// pub(crate) fn gen_address_seed_with_salt_hash(
//     salt_hash: &str,
//     name: &str,  // i.e. "sub"
//     value: &str, // i.e. the sub value
//     aud: &str,   // i.e. the client ID
// ) -> String {
//     Ok(poseidon_zk_login(&[
//         hash_ascii_str_to_field(name, MAX_KEY_CLAIM_NAME_LENGTH)?,
//         hash_ascii_str_to_field(value, MAX_KEY_CLAIM_VALUE_LENGTH)?,
//         hash_ascii_str_to_field(aud, MAX_AUD_VALUE_LENGTH)?,
//         (&Bn254FrElement::from_str(salt_hash)?).into(),
//     ])?
//     .to_string())
// }


pub fn split_email(email: String) -> Result<EmailParts, Error> {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid email format");
    }

    Ok(EmailParts {
        username: parts[0].to_string(),
        domain: parts[1].to_string(),
    })
}

// slightly modified version of https://github.com/robjsliwa/jwt-rustcrypto/blob/main/src/decode.rs#L80
pub fn split_jwt(token: &str) -> Result<(Header, JsonValue, Vec<u8>), Error> {
    let parts: Vec<&str> = token.split('.').collect();

    let header_data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0])?;
    let payload_data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])?;

    let header: Header = serde_json::from_slice(&header_data)?;
    let payload: JsonValue = serde_json::from_slice(&payload_data)?;

    Ok((header, payload, signature))
}


pub fn pem_to_der(pem_key: &str) -> Vec<u8> {
    let key_lines: Vec<&str> = pem_key
        .lines()
        .filter(|line| 
            !line.contains("BEGIN PUBLIC KEY") && 
            !line.contains("END PUBLIC KEY")
        )
        .collect();
    let base64_key = key_lines.join("");
    general_purpose::STANDARD
        .decode(&base64_key)
        .expect("Failed to decode base64")
}



#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES256K,
    ES384,
    ES512,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let alg_str = match self {
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::PS256 => "PS256",
            Algorithm::PS384 => "PS384",
            Algorithm::PS512 => "PS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES256K => "ES256K",
            Algorithm::ES384 => "ES384",
            Algorithm::ES512 => "ES512",
        };
        write!(f, "{}", alg_str)
    }
}

impl FromStr for Algorithm {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HS256" => Ok(Algorithm::HS256),
            "HS384" => Ok(Algorithm::HS384),
            "HS512" => Ok(Algorithm::HS512),
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "RS512" => Ok(Algorithm::RS512),
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            "ES512" => Ok(Algorithm::ES512),
            _ => Err(format!("Unsupported algorithm: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub alg: Algorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
}