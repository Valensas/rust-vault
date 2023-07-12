use crate::vault::vault_config::VaultConfig;
use crate::vault::vault_service::VaultService;
use async_trait::async_trait;
use std::error;
use std::io;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

#[async_trait]
pub trait AuthenticateVault {
    async fn authenticate(
        &self,
        config: VaultConfig,
    ) -> Result<VaultService, Box<dyn error::Error>> {
        let settings: VaultClientSettingsBuilder = self.get_vault_settings(&config);

        let jwt_token = self.get_jwt_token(&config);

        let client: VaultClient = self.create_client(settings)?;

        Ok(self.create_service(client, &config, jwt_token).await?)
    }

    fn get_vault_settings(&self, _: &VaultConfig) -> VaultClientSettingsBuilder;

    fn get_jwt_token(&self, _: &VaultConfig) -> Option<Result<String, io::Error>>;

    fn create_client(
        &self,
        settings: VaultClientSettingsBuilder,
    ) -> Result<VaultClient, Box<dyn error::Error>> {
        match VaultClient::new(settings.build()?) {
            Ok(result) => Ok(result),
            Err(err) => Err(err.into()),
        }
    }

    async fn create_service(
        &self,
        _: VaultClient,
        _: &VaultConfig,
        _: Option<Result<String, io::Error>>,
    ) -> Result<VaultService, Box<dyn error::Error>>;
}
