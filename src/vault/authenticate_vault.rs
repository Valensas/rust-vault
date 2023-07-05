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

#[async_trait]
pub trait AuthenticateVault {
    async fn authenticate(&self, config: VaultConfig) -> Result<VaultService, VaultError> {
        let settings: VaultClientSettingsBuilder = self.get_vault_settings(config.clone());

        let jwt_token = self.get_jwt_token(config.clone()).unwrap().unwrap();

        let client: VaultClient = self.create_client(settings);

        return self.create_service(client, config, jwt_token).await;
    }

    fn get_vault_settings(&self, config: VaultConfig) -> VaultClientSettingsBuilder;

    fn get_jwt_token(&self, config: VaultConfig) -> Result<Option<String>, VaultError>;

    fn create_client(&self, settings: VaultClientSettingsBuilder) -> VaultClient {
        return VaultClient::new(settings.build().unwrap()).unwrap();
    }

    async fn create_service(&self, client: VaultClient, config: VaultConfig, token: String) -> Result<VaultService, VaultError>;
}

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
    async fn create_service(&self, mut client: VaultClient, config: VaultConfig, token: String) -> Result<VaultService, VaultError> {
        let auth_info: Option<AuthInfo> = match kubernetes::login(&client, "kubernetes", config.role_name.clone().unwrap().as_str(), &token.trim()).await {
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

    async fn create_service(&self, client: VaultClient, config: VaultConfig, _: String) -> Result<VaultService, VaultError> {
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