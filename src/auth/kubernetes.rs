use crate::auth::method::AuthMethod;
use async_trait::async_trait;
use vaultrs::client::Client;
use std::error::Error;
use std::sync::Arc;
use std::{fs, io};
use vaultrs::{
    auth::kubernetes,
    client::VaultClient
};

use super::method::AuthResult;

#[derive(Debug)]
pub struct KubernetesAuth {
    mount: String,
    role: String,
    token: String
}

impl KubernetesAuth {
    pub fn new(mount: Option<String>, sa_token_path: Option<String>) -> Result<Self, io::Error> {
        let token = fs::read_to_string(sa_token_path.unwrap_or("/var/run/kubernetes.io/serviceaccount/token".to_string()))?;

        Ok(Self {
            mount: mount.unwrap_or("kubernetes".to_string()),
            token,
            role: todo!("fill role")
        })
    }
}

#[async_trait]
impl AuthMethod for KubernetesAuth {
    async fn authenticate(&self, client: Arc<VaultClient>) -> Result<AuthResult, Box<dyn Error>> {
        let auth_info = kubernetes::login(
            client.as_ref(),
            &self.mount,
            &self.role,
            &self.token,
         )
         .await?;
        client.set_token(&auth_info.client_token);
        Ok(AuthResult::auth_info(auth_info))
    }
}
