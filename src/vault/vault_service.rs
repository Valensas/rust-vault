#![allow(non_snake_case)]

use std::{sync::{Arc, RwLock}};
use std::error;
use rocket::futures::executor::block_on;
use rustify::clients::reqwest::Client as HTTPClient;
use serde::{Deserialize, Serialize};
use tokio::task::{JoinHandle};
use vaultrs::{
    api::AuthInfo,
    client::{Client, VaultClient},
    kv2,
};
use vaultrs::api::kv2::responses::{SecretVersionMetadata};
use vaultrs::error::ClientError;
use crate::vault::authenticate_vault::authenticate_vault_trait::AuthenticateVault;
use crate::vault::authenticate_vault::kubernetes::AuthenticateKubernetesVault;
use crate::vault::authenticate_vault::token::AuthenticateTokenVault;
use crate::vault::vault_config::{AuthMethod, VaultConfig};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HealthCheckData {
    pub data: String,
}

pub struct VaultService {
    pub client: VaultClient,
    pub(crate) config: VaultConfig,
    pub auth_info: Option<AuthInfo>,
}

impl std::fmt::Debug for VaultService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultService")
            .field("config", &self.config)
            .field("auth_info", &self.auth_info)
            .finish()
    }
}

impl Clone for VaultService {
    fn clone(&self) -> Self {
        let http_client = HTTPClient {
            http: self.client.http.http.clone(),
            base: self.client.http.base.clone(),
        };
        let client = VaultClient {
            http: http_client,
            middle: self.client.middle.clone(),
            settings: self.client.settings.clone(),
        };
        let auth_info = match &self.auth_info {
            Some(res) => {
                let auth_instance = res;
                Some(AuthInfo {
                    client_token: auth_instance.client_token.clone(),
                    accessor: auth_instance.accessor.clone(),
                    policies: auth_instance.policies.clone(),
                    token_policies: auth_instance.token_policies.clone(),
                    metadata: auth_instance.metadata.clone(),
                    lease_duration: auth_instance.lease_duration,
                    renewable: auth_instance.renewable,
                    entity_id: auth_instance.entity_id.clone(),
                    token_type: auth_instance.token_type.clone(),
                    orphan: auth_instance.orphan,
                })
            }
            None => None,
        };
        Self {
            auth_info,
            client,
            config: self.config.clone(),
        }
    }
}

impl VaultService {
    pub async fn new() -> Result<Self, Box<dyn error::Error>> {
        let config: VaultConfig = VaultConfig::loadEnv()?;
        match config.auth_method {
            AuthMethod::Token => { AuthenticateTokenVault.authenticate(config).await }
            AuthMethod::Kubernetes => { AuthenticateKubernetesVault.authenticate(config).await }
        }
    }

    pub async fn renewToken(&mut self) {
        log::debug!("vault token renewal began");
        match self.client.renew(None).await {
            Ok(res) => {
                self.client.set_token(&res.client_token);
                self.auth_info = Some(res);
                log::info!("vault token renewal is successfull");
            }
            Err(err) => {
                log::info!("an error occured during token renewal\n{}", err);
            }
        }
    }

    pub async fn insert<T: serde::Serialize>(&self, key: &str, data: T) -> Result<SecretVersionMetadata, ClientError> {
        match kv2::set(&self.client, &self.config.mount_path, key, &data).await {
            Ok(result) => { Ok(result) }
            Err(err) => { Err(err) }
        }
    }

    pub async fn read<'a, T: for<'de> serde::Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<T, ClientError> {
        match kv2::read(&self.client, &self.config.mount_path, key).await {
            Ok(result) => { Ok(result) }
            Err(err) => { Err(err) }
        }
    }

    async fn versions(&self, key: &str) -> Result<Vec<u64>, ClientError> {
        let secret_metadata = kv2::read_metadata(
            &self.client,
            &self.config.mount_path,
            key,
        ).await;

        match secret_metadata {
            Ok(secret) => {
                Ok(
                    secret
                        .versions.into_iter()
                        .map(|x| x.0.parse::<u64>().unwrap())
                        .collect()
                )
            }
            Err(err) => {
                Err(err)
            }
        }
    }

    pub async fn delete(&self, key: &str) -> Result<(), ClientError> {
        let version_result = self.versions(key).await?;

        match kv2::delete_versions(&self.client, &self.config.mount_path, key, version_result).await {
            Ok(result) => { Ok(result) }
            Err(err) => { Err(err) }
        }
    }

    pub async fn permanently_delete(&self, key: &str) -> Result<(), ClientError> {
        let version = self.versions(key).await?;

        match kv2::destroy_versions(&self.client, &self.config.mount_path, key, version).await {
            Ok(result) => { Ok(result) }
            Err(err) => { Err(err) }
        }
    }

    pub async fn clearHealthFile(&self) -> Result<(), ClientError> {
        let path = self.config.healthcheck_file_path.clone();
        self.delete(&path).await?;
        self.permanently_delete(&path).await
    }

    pub async fn setupHealthCheckFile(&self) -> Result<bool, ClientError> {
        let data = HealthCheckData {
            data: "health check file".to_string(),
        };
        let path = self.config.healthcheck_file_path.clone();
        match self.insert(path.as_str(), data).await {
            Ok(_) => Ok(true),
            Err(err) => Err(err),
        }
    }
}

pub async fn tokenRenewalCycle(
    cloned_service: Arc<RwLock<VaultService>>
) -> Option<JoinHandle<Result<(), ClientError>>> {
    let x: Option<JoinHandle<_>> = match cloned_service.clone().read() {
        Ok(res) => {
            match res.clone().auth_info {
                Some(res) => {
                    if res.renewable {
                        let handler = tokio::spawn(async move {
                            let time = chrono::Duration::seconds(
                                (res.lease_duration - 5).try_into().unwrap()
                            );
                            let mut interval = tokio::time::interval(time.to_std().unwrap());
                            interval.tick().await;
                            loop {
                                interval.tick().await;
                                let cloned_cloned_vault = Arc::clone(&cloned_service);
                                block_on(async {
                                    match cloned_cloned_vault.write() {
                                        Ok(mut res) => { res.renewToken().await }
                                        Err(err) => {
                                            log::error!("{}", err);
                                        }
                                    }
                                });
                            }
                        });
                        Some(handler)
                    } else {
                        None
                    }
                }
                None => None,
            }
        }
        Err(err) => {
            panic!("{}", err);
        }
    };
    x
}

pub async fn tokenRenewalAbortion(
    token_renewal_handler: Option<JoinHandle<Result<(), ClientError>>>
) {
    if let Some(res) = token_renewal_handler {
        res.abort();
        match res.await {
            Ok(_) => {
                log::info!("token renewal stopped gracefully");
            }
            Err(err) => {
                if err.is_cancelled() {
                    log::info!("token renewal stopped gracefully");
                } else {
                    log::error!("token renewal err {}", err);
                }
            }
        }
    }
}