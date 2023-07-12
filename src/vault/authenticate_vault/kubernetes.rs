use std::fs::File;
use std::io;
use std::io::Read;
use crate::vault::vault_config::VaultConfig;
use crate::vault::vault_service::VaultService;
use vaultrs::{
    api::AuthInfo,
    auth::kubernetes,
    client::{Client, VaultClient, VaultClientSettingsBuilder},
};
use async_trait::async_trait;
use vaultrs::error::ClientError;
use crate::vault::authenticate_vault::authenticate_vault_trait::AuthenticateVault;

pub struct AuthenticateKubernetesVault;

#[async_trait]
impl AuthenticateVault for AuthenticateKubernetesVault {
    fn get_vault_settings(&self, config: &VaultConfig) -> VaultClientSettingsBuilder {
        VaultClientSettingsBuilder::default()
            .address(config.address.clone())
            .timeout(Some(config.client_timeout)).clone()
    }

    fn get_jwt_token(&self, config: &VaultConfig) -> Result<Option<String>, io::Error> {
        let mut token = String::new();
        let mut file: File = match File::open(config.clone().token_path.unwrap().as_str()) {
            Ok(file) => { file }
            Err(err) => { return Err(err); }
        };
        match file.read_to_string(&mut token) {
            Ok(_) => { Ok(Some(token)) }
            Err(err) => {
                Err(err)
            }
        }
    }
    async fn create_service(&self, mut client: VaultClient, config: &VaultConfig, token: Option<String>) -> Result<VaultService, ClientError> {
        let auth_info: Option<AuthInfo> = match kubernetes::login(&client, config.mount_path.as_str(), config.role_name.clone().unwrap().as_str(), token.unwrap().trim()).await {
            Ok(res) => {
                client.set_token(&res.client_token);
                Some(res)
            }
            Err(err) => {
                return Err(err);
            }
        };

        Ok(
            VaultService {
                client,
                config: config.clone(),
                auth_info,
            }
        )
    }
}