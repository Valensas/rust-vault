use async_trait::async_trait;
use tokio::sync::RwLock;
use vaultrs::{
    api::AuthInfo,
    client::VaultClient
};
use std::{
    error::Error,
    fmt::Debug,
    sync::Arc,
};

#[derive(Debug)]
pub enum AuthResult {
    Token { token: String },
    AuthInfo { auth_info: AuthInfo },
}

impl AuthResult {
    pub fn token(token: String) -> AuthResult {
        AuthResult::Token { token }
    }

    pub fn auth_info(auth_info: AuthInfo) -> AuthResult {
        AuthResult::AuthInfo { auth_info }
    }
}

#[async_trait]
pub trait AuthMethod: Debug + Send + Sync {
    async fn authenticate(
        &self,
        client: Arc<RwLock<VaultClient>>,
    ) -> Result<AuthResult, Box<dyn Error>>;
}
