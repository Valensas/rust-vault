use std::io::Error;
use crate::vault::vault_config::VaultConfig;
use crate::vault::vault_service::VaultService;
use vaultrs::{
    client::{VaultClient, VaultClientSettingsBuilder},
};
use async_trait::async_trait;
use vaultrs::error::ClientError;

#[async_trait]
pub trait AuthenticateVault {
    async fn authenticate(&self, config: VaultConfig) -> Result<VaultService, ClientError> {
        let settings: VaultClientSettingsBuilder = self.get_vault_settings(&config);

        let jwt_token = self.get_jwt_token(&config).unwrap();

        let client: VaultClient = self.create_client(settings);

        return self.create_service(client, &config, jwt_token).await;
    }

    fn get_vault_settings(&self, config: &VaultConfig) -> VaultClientSettingsBuilder;

    fn get_jwt_token(&self, config: &VaultConfig) -> Result<Option<String>, Error>;

    fn create_client(&self, settings: VaultClientSettingsBuilder) -> VaultClient {
       VaultClient::new(settings.build().unwrap()).unwrap()
    }

    async fn create_service(&self, client: VaultClient, config: &VaultConfig, token: Option<String>) -> Result<VaultService, ClientError>;
}
