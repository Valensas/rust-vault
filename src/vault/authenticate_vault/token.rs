use crate::errors::error::VaultError;
use crate::vault::vault_config::VaultConfig;
use crate::vault::vault_service::VaultService;
use vaultrs::{
    client::{Client, VaultClient, VaultClientSettingsBuilder},
};
use async_trait::async_trait;
use crate::vault::authenticate_vault::authenticate_vault_trait::AuthenticateVault;

pub struct AuthenticateTokenVault;

#[async_trait]
impl AuthenticateVault for AuthenticateTokenVault {
    fn get_vault_settings(&self, config: VaultConfig) -> VaultClientSettingsBuilder {
        return VaultClientSettingsBuilder::default()
            .address(config.address.clone())
            .token(config.token.clone().unwrap())
            .timeout(Some(config.client_timeout)).clone()
    }

    fn get_jwt_token(&self, _: VaultConfig) -> Result<Option<String>, VaultError> {
        return Ok(None);
    }

    async fn create_service(&self, client: VaultClient, config: VaultConfig, _: Option<String>) -> Result<VaultService, VaultError> {
        return match client.status().await {
            Ok(_) => {
                Ok(
                    VaultService {
                        client,
                        config,
                        auth_info: None,
                    }
                )
            }
            Err(err) => {
                Err(VaultError::new(format!("Vault could not authenticated with 'Token' auth:\n{}", err)))
            }
        };
    }
}