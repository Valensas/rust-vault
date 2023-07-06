use std::fs::File;
use std::io::Read;
use crate::errors::error::VaultError;
use crate::vault::vault_config::VaultConfig;
use crate::vault::vault_service::VaultService;
use vaultrs::{
    api::AuthInfo,
    auth::kubernetes,
    client::{Client, VaultClient, VaultClientSettingsBuilder},
};
use async_trait::async_trait;
use crate::vault::authenticate_vault::authenticate_vault_trait::AuthenticateVault;

pub struct AuthenticateKubernetesVault;

#[async_trait]
impl AuthenticateVault for AuthenticateKubernetesVault {
    fn get_vault_settings(&self, config: VaultConfig) -> VaultClientSettingsBuilder {
        return VaultClientSettingsBuilder::default()
            .address(config.address.clone())
            .timeout(Some(config.client_timeout)).clone();
    }

    fn get_jwt_token(&self, config: VaultConfig) -> Result<Option<String>, VaultError> {
        let mut token = String::new();
        let mut file = match File::open(config.clone().token_path.unwrap().as_str()) {
            Ok(res) => res,
            Err(err) => {
                return Err(VaultError::new(format!("File does not exists in given path: {}\n{}", config.token_path.clone().unwrap(), err)));
            }
        };
        return match file.read_to_string(&mut token) {
            Ok(_) => { Ok(Some(token)) }
            Err(err) => {
                Err(VaultError::new(err.to_string()))
            }
        };
    }
    async fn create_service(&self, mut client: VaultClient, config: VaultConfig, token: Option<String>) -> Result<VaultService, VaultError> {
        let auth_info: Option<AuthInfo> = match kubernetes::login(&client, "kubernetes", config.role_name.clone().unwrap().as_str(), &token.unwrap().trim()).await {
            Ok(res) => {
                client.set_token(&res.client_token);
                Some(res)
            }
            Err(err) => {
                return Err(VaultError::new(format!("Vault could not authenticated with 'Kubernetes' auth:\n{}", err)));
            }
        };

        return Ok(
            VaultService {
                client,
                config,
                auth_info,
            }
        );
    }
}