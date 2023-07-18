use crate::vault::authenticate_vault::authenticate_vault_trait::AuthenticateVault;
use crate::vault::authenticate_vault::kubernetes::AuthenticateKubernetesVault;
use crate::vault::authenticate_vault::token::AuthenticateTokenVault;
use crate::vault::vault_config::{AuthMethod, VaultConfig};
use rocket::futures::executor::block_on;
use rustify::clients::reqwest::Client as HTTPClient;
use serde::{Deserialize, Serialize};
use std::error;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc, mpsc::Sender};
use tokio::task::JoinHandle;
use vaultrs::api::kv2::responses::SecretVersionMetadata;
use vaultrs::error::ClientError;
use vaultrs::{
    api::AuthInfo,
    client::{Client, VaultClient},
    kv2,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HealthCheckData {
    pub(crate) data: String,
}

pub struct VaultService {
    pub(crate) client: VaultClient,
    pub(crate) config: VaultConfig,
    pub(crate) auth_info: Option<AuthInfo>,
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
        let config: VaultConfig = VaultConfig::load_env()?;
        match config.auth_method {
            AuthMethod::Token => AuthenticateTokenVault.authenticate(config).await,
            AuthMethod::Kubernetes => AuthenticateKubernetesVault.authenticate(config).await,
        }
    }

    async fn renew_token(&mut self) -> Result<(), ClientError> {
        log::debug!("vault token renewal began");
        match self.client.renew(None).await {
            Ok(res) => {
                self.client.set_token(&res.client_token);
                self.auth_info = Some(res);
                log::info!("vault token renewal is successful");
                Ok(())
            }
            Err(err) => {
                log::info!("an error occurred during token renewal\n{}", err);
                err
            }
        }
    }

    pub async fn insert<T: serde::Serialize>(
        &self,
        key: &str,
        data: T,
    ) -> Result<SecretVersionMetadata, ClientError> {
        match kv2::set(&self.client, &self.config.mount_path, key, &data).await {
            Ok(result) => Ok(result),
            Err(err) => Err(err),
        }
    }

    pub async fn read<'a, T: for<'de> serde::Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<T, ClientError> {
        match kv2::read(&self.client, &self.config.mount_path, key).await {
            Ok(result) => Ok(result),
            Err(err) => Err(err),
        }
    }

    async fn versions(&self, key: &str) -> Result<Vec<u64>, ClientError> {
        let secret_metadata = kv2::read_metadata(&self.client, &self.config.mount_path, key).await;

        match secret_metadata {
            Ok(secret) => Ok(secret
                .versions
                .into_iter()
                .map(|x| x.0.parse::<u64>().unwrap())
                .collect()),
            Err(err) => Err(err),
        }
    }

    pub async fn delete(&self, key: &str) -> Result<(), ClientError> {
        let version_result = self.versions(key).await?;

        match kv2::delete_versions(&self.client, &self.config.mount_path, key, version_result).await
        {
            Ok(result) => Ok(result),
            Err(err) => Err(err),
        }
    }

    pub async fn delete_permanent(&self, key: &str) -> Result<(), ClientError> {
        let version = self.versions(key).await?;

        match kv2::destroy_versions(&self.client, &self.config.mount_path, key, version).await {
            Ok(result) => Ok(result),
            Err(err) => Err(err),
        }
    }

    pub async fn healthcheck(&self) -> Result<(), ClientError> {
        match self
            .read::<HealthCheckData>(self.config.healthcheck_file_path.as_str())
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => err,
        }
    }

    pub async fn clear_healthcheck_file(&self) -> Result<(), ClientError> {
        let path = self.config.healthcheck_file_path.clone();
        self.delete(&path).await?;
        self.delete_permanent(&path).await
    }

    pub async fn setup_healthcheck_file(&self) -> Result<bool, ClientError> {
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

pub async fn token_renewal(
    cloned_service: Arc<RwLock<VaultService>>,
) -> Option<(JoinHandle<Result<(), ClientError>>, Sender<bool>)> {
    let vault_lock;
    while let res = cloned_service.clone().read() {
        if res.is_err() {
            continue;
        }
        vault_lock = res.unwrap()
    }
    return match vault_lock.clone().auth_info {
        Some(auth_info) => {
            if auth_info.renewable {
                let (sender, mut receiver) = mpsc::channel::<bool>(1);
                let handler = inner_token_renewal(cloned_service.clone(), receiver);
                Some((handler, sender))
            } else {
                None
            }
        }
        None => None,
    };
}

pub fn inner_token_renewal(
    cloned_service: Arc<RwLock<VaultService>>,
    mut receiver: Receiver<bool>,
) -> JoinHandle<Result<(), ClientError>> {
    tokio::spawn(async move {
        let time = chrono::Duration::seconds((res.lease_duration - 5).try_into().unwrap());
        let mut interval = tokio::time::interval(time.to_std().unwrap());
        interval.tick().await;

        loop {
            interval.tick().await;
            let cloned_cloned_vault = Arc::clone(&cloned_service);
            block_on(async {
                if let Ok(true) = receiver.try_recv() {
                    break;
                }
                match cloned_cloned_vault.write() {
                    Ok(mut res) => res.renew_token()?.await,
                    Err(err) => {
                        log::error!("{}", err);
                        return err;
                    }
                }
            });
        }
        Ok(())
    })
}

pub async fn token_renewal_abortion(
    token_renewal_handler: (JoinHandle<Result<(), ClientError>>, Sender<bool>),
) {
    let (res, sender) = token_renewal_handler;

    while let Err(err) = sender.send(true).await {
        log::error!("{}", err);
    }

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
