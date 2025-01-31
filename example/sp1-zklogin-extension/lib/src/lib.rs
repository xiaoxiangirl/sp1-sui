// Custom structs with seralize/deserialize.

use anyhow::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use base64::{engine::general_purpose, Engine as _};

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailParts {
    pub username: String,
    pub domain: String,
}

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
pub fn split_jwt(token: &str) -> Result<(JsonValue, Vec<u8>), Error> {
    let parts: Vec<&str> = token.split('.').collect();

    //let header_data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0])?;
    let payload_data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])?;

    //let header: Header = serde_json::from_slice(&header_data)?;
    let payload: JsonValue = serde_json::from_slice(&payload_data)?;

    Ok((payload, signature))
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