use crate::auth::method::{AuthResult, AuthMethod};
use crate::config::VaultConfig;

use async_trait::async_trait;
use futures::executor::block_on;
use serde::{Deserialize, Serialize};
use std::{error::{self, Error}, sync::Arc};
use tokio::{sync::{RwLock, mpsc::{Receiver, Sender, channel}}, task::JoinHandle};
use vaultrs::{
    client::{Client, VaultClient, VaultClientSettingsBuilder},
    kv2,
    api::kv2::responses::SecretVersionMetadata
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HealthCheckData {
    pub(crate) data: String,
}

pub struct VaultService {
    pub(crate) client: Arc<RwLock<VaultClient>>,
    pub(crate) auth_result: AuthResult,
    pub(crate) mount_path: String,
    pub(crate) healthcheck_file_path: String,
}

impl std::fmt::Debug for VaultService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultService")
        .field("auth_result", &self.auth_result)
        .finish()
    }
}

impl VaultService {
    pub async fn from_env() -> Result<(Arc<RwLock<Self>>, Arc<RwLock<dyn AuthMethod>>), Box<dyn error::Error>> {
        let (config, auth_method) = VaultConfig::from_env()?;
        let auth = Arc::clone(&auth_method);

        Self::new(config, auth)
        .await
        .map(|vs| (vs, auth_method))
    }

    pub async fn new(config: VaultConfig, auth_method: Arc<RwLock<dyn AuthMethod>>) -> Result<Arc<RwLock<Self>>, Box<dyn error::Error>> {
        let settings = VaultClientSettingsBuilder::default()
            .address(config.address.clone())
            .timeout(Some(config.client_timeout))
            .build()?;

        let client = Arc::new(RwLock::new(VaultClient::new(settings)?));
        let auth_client = Arc::clone(&client);
        let auth_result = auth_method
            .as_ref()
            .read().await
            .authenticate(auth_client)
            .await?;

        Ok(Arc::new(RwLock::new(Self {
            mount_path: config.mount_path,
            healthcheck_file_path: config.healthcheck_file_path,
            client,
            auth_result,
        })))
    }

    pub async fn insert<T: serde::Serialize>(
        &self,
        key: &str,
        data: T,
    ) -> Result<SecretVersionMetadata, Box<dyn Error>> {
        kv2::set(
            &*self.client.read().await,
            &self.mount_path,
            key,
            &data,
        )
        .await
        .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub async fn read<'a, T: for<'de> serde::Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<T, Box<dyn Error>> {
        kv2::read(&*self.client.read().await, &self.mount_path, key)
        .await
        .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    async fn versions(&self, key: &str) -> Result<Vec<u64>, Box<dyn Error>> {
        let secret_metadata =
        kv2::read_metadata(&*self.client.read().await, &self.mount_path, key).await;

        match secret_metadata {
            Ok(secret) => Ok(secret
                .versions
                .into_iter()
                .map(|x| x.0.parse::<u64>().unwrap())
                .collect()),
            Err(err) => Err(Box::new(err)),
        }
    }

    pub async fn delete(&self, key: &str) -> Result<(), Box<dyn Error>> {
        let version_result = self.versions(key).await?;

        kv2::delete_versions(
            &*self.client.read().await,
            &self.mount_path,
            key,
            version_result,
        )
        .await
        .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub async fn delete_permanent(&self, key: &str) -> Result<(), Box<dyn Error>> {
        let version = self.versions(key).await?;

        kv2::destroy_versions(
            &*self.client.read().await,
            &self.mount_path,
            key,
            version,
        )
        .await
        .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub async fn healthcheck(&self) -> Result<(), Box<dyn Error>> {
        self.read::<HealthCheckData>(self.healthcheck_file_path.as_str())
        .await?;
        Ok(())
    }

    pub async fn clear_healthcheck_file(&self) -> Result<(), Box<dyn Error>> {
        let path = self.healthcheck_file_path.clone();
        self.delete(&path).await?;
        self.delete_permanent(&path).await
    }

    pub async fn setup_healthcheck_file(&self) -> Result<(), Box<dyn Error>> {
        let data = HealthCheckData {
            data: "health check file".to_string(),
        };
        let path = self.healthcheck_file_path.clone();
        self.insert(path.as_str(), data).await?;
        Ok(())
    }

    async fn renew_token(&mut self) -> Result<(), Box<dyn Error + '_>> {
        log::debug!("Renewing Vault token");
        let mut client = self.client.write().await;
        match client.renew(None).await {
            Ok(auth_info) => {
                client.set_token(&auth_info.client_token);
                drop(client);
                self.auth_result = AuthResult::auth_info(auth_info);
                log::info!("Successfully renewed Vault token");
                Ok(())
            }
            Err(err) => {
                log::info!("An error occurred during Vault token renewal\n{}", err);
                Err(Box::new(err))
            }
        }
    }
}

type ThreadHandler = Option<(JoinHandle<()>, Sender<()>)>;

#[async_trait]
pub trait TokenRenewable {
    fn start_token_renewal(&self, auth_method: Arc<RwLock<dyn AuthMethod>>) -> Result<ThreadHandler, Box<dyn Error>>;

    fn start_token_renew_loop(
        &self,
        lease_duration: u64,
        sender: Sender<()>,
        receiver: Receiver<()>,
        auth_method: Arc<RwLock<dyn AuthMethod>>
    ) -> (JoinHandle<()>, Sender<()>);

    async fn stop_token_renew_loop(&self, handler: (JoinHandle<()>, Sender<()>));
}

#[async_trait]
impl TokenRenewable for Arc<RwLock<VaultService>> {
    /// Start token renewal for `VaultClient` periodically.
    /// Periods determined from `lease_duration` value of the `auth_info`.
    fn start_token_renewal(&self, auth_method: Arc<RwLock<dyn AuthMethod>>) -> Result<ThreadHandler, Box<dyn Error>> {
        let locked_service = block_on(self.read());
        if let AuthResult::AuthInfo { auth_info } = &locked_service.auth_result {
            if !auth_info.renewable {
                return Ok(None);
            }
            let (sender, receiver) = channel::<()>(1);
            let handler = self.start_token_renew_loop(auth_info.lease_duration, sender, receiver, auth_method);
            Ok(Some(handler))
        } else {
            Ok(None)
        }
    }

    /// This function handles the inner loops for `start_token_renewal` function.
    /// It is not recommended to use manually.
    /// Instead of this function, use `start_token_renewal` directly
    fn start_token_renew_loop(
        &self,
        lease_duration: u64,
        sender: Sender<()>,
        mut receiver: Receiver<()>,
        auth_method: Arc<RwLock<dyn AuthMethod>>
    ) -> (JoinHandle<()>, Sender<()>) {
        let service = Arc::clone(self);
        (tokio::spawn(async move {
            let time = std::time::Duration::new(lease_duration - 5, 0);
            let mut interval = tokio::time::interval(time);
            loop {
                let auth_method_lock = auth_method.read().await;
                interval.tick().await;
                if receiver.recv().await.is_some() {
                    break;
                }
                let mut renew_token_trial = false;
                for _ in 0..5 {
                    let mut lock = service.write().await;
                    match lock.renew_token().await {
                        Ok(_) => {
                            renew_token_trial = true;
                            break;
                        },
                        Err(err) => {
                            log::error!("retring to renew token: {}", err);
                        }
                    };
                };
                if !renew_token_trial {
                    let lock = &*service.read().await;
                    let client = &lock.client;
                    if let Err(err) = auth_method_lock.authenticate(client.clone()).await {
                        log::error!("{}", err);
                    };
                }
            }
        }), sender)
    }

    async fn stop_token_renew_loop(&self, handler: (JoinHandle<()>, Sender<()>)) {
        let (handler, sender) = handler;
        let _ = sender.send(()).await;
        handler.abort();
    }
}