use crate::vault::authenticate_vault::authenticate_vault_trait::AuthenticateVault;
use crate::vault::vault_config::VaultConfig;
use crate::vault::vault_service::VaultService;
use async_trait::async_trait;
use std::error;
use std::{fs, io};
use vaultrs::{
    auth::kubernetes,
    client::{Client, VaultClient, VaultClientSettingsBuilder},
};

pub struct AuthenticateKubernetesVault;

#[async_trait]
impl AuthenticateVault for AuthenticateKubernetesVault {
    fn get_vault_settings(&self, config: &VaultConfig) -> VaultClientSettingsBuilder {
        VaultClientSettingsBuilder::default()
            .address(config.address.clone())
            .timeout(Some(config.client_timeout))
            .clone()
    }

    fn get_jwt_token(&self, config: &VaultConfig) -> Option<Result<String, io::Error>> {
        Some(fs::read_to_string(config.clone().token_path?.as_str()))
    }
    async fn create_service(
        &self,
        mut client: VaultClient,
        config: &VaultConfig,
        token: Option<Result<String, io::Error>>,
    ) -> Result<VaultService, Box<dyn error::Error>> {
        let auth_info = kubernetes::login(
            &client,
            config.mount_path.as_str(),
            config.role_name.clone().unwrap().as_str(),
            token.unwrap()?.trim(),
        )
        .await?;

        client.set_token(&auth_info.client_token);
        let auth = Some(auth_info);

        Ok(VaultService {
            client,
            config: config.clone(),
            auth_info: auth,
        })
    }
}
