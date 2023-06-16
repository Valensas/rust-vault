use std::{ error::Error, fmt };

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct VaultError {
    description: String,
}

impl VaultError {
    pub fn new(description: String) -> Self {
        Self { description }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}

impl Error for VaultError {
    fn description(&self) -> &str {
        &self.description
    }
}
