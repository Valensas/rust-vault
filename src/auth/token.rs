use std::sync::Arc;

use crate::auth::method::AuthMethod;
use async_trait::async_trait;
use vaultrs::client::{VaultClient, Client};

use super::method::AuthResult;

#[derive(Debug)]
pub struct TokenAuth {
    token: String
}

impl TokenAuth {
    pub fn new(token: String) -> Self {
        Self {
            token
        }
    }
}

#[async_trait]
impl AuthMethod for TokenAuth {
    async fn authenticate(&self, client: Arc<VaultClient>) -> Result<AuthResult, Box<dyn std::error::Error>> {
        client.set_token(&self.token);
        Ok(AuthResult::token(self.token))
    }
}