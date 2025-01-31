// Custom structs with seralize/deserialize.

use anyhow::Error;
use serde::{Deserialize, Serialize};

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
