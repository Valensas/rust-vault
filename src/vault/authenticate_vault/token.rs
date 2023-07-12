use crate::vault::authenticate_vault::authenticate_vault_trait::AuthenticateVault;
use crate::vault::vault_config::VaultConfig;
use crate::vault::vault_service::VaultService;
use async_trait::async_trait;
use std::io;
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;

pub struct AuthenticateTokenVault;

#[async_trait]
impl AuthenticateVault for AuthenticateTokenVault {
    fn get_vault_settings(&self, config: &VaultConfig) -> VaultClientSettingsBuilder {
        return VaultClientSettingsBuilder::default()
            .address(config.address.clone())
            .token(config.token.clone().unwrap())
            .timeout(Some(config.client_timeout))
            .clone();
    }

    fn get_jwt_token(&self, _: &VaultConfig) -> Result<Option<String>, io::Error> {
        Ok(None)
    }

    async fn create_service(
        &self,
        client: VaultClient,
        config: &VaultConfig,
        _: Option<String>,
    ) -> Result<VaultService, ClientError> {
        return match client.status().await {
            Ok(_) => Ok(VaultService {
                client,
                config: config.clone(),
                auth_info: None,
            }),
            Err(err) => Err(err),
        };
    }
}
