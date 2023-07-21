use crate::auth;
use crate::auth::method::AuthResult;
use crate::vault_config::VaultConfig;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::error::{self, Error};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc, mpsc::Sender};
use tokio::task::JoinHandle;
use vaultrs::api::kv2::responses::SecretVersionMetadata;
use vaultrs::client::VaultClientSettingsBuilder;
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
    pub(crate) client: Arc<RwLock<VaultClient>>,
    pub(crate) config: VaultConfig,
    pub(crate) auth_result: AuthResult,
}

impl std::fmt::Debug for VaultService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultService")
        .field("config", &self.config)
        .field("auth_result", &self.auth_result)
        .finish()
    }
}

impl VaultService {
    pub async fn new(config: VaultConfig) -> Result<Self, Box<dyn error::Error>> {
        let settings = VaultClientSettingsBuilder::default()
        .address(config.address.clone())
        .timeout(Some(config.client_timeout))
        .build()?;

        let client = Arc::new(RwLock::new(VaultClient::new(settings)?));
        let auth_result = config
        .auth_method
        .as_ref()
        .authenticate(Arc::clone(&client))
        .await?;

        Ok(Self {
            config,
            client,
            auth_result,
        })
    }

    pub(crate) fn write_lock_client(
        &self,
    ) -> Result<RwLockWriteGuard<'_, VaultClient>, Box<dyn Error>> {
        self.client
        .write()
        .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub(crate) fn read_lock_client(
        &self,
    ) -> Result<RwLockReadGuard<'_, VaultClient>, Box<dyn Error>> {
        self.client
        .read()
        .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub async fn insert<T: serde::Serialize>(
        &self,
        key: &str,
        data: T,
    ) -> Result<SecretVersionMetadata, Box<dyn Error>> {
        kv2::set(
            &*self.read_lock_client()?,
            &self.config.mount_path,
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
        kv2::read(&*self.read_lock_client()?, &self.config.mount_path, key)
        .await
        .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    async fn versions(&self, key: &str) -> Result<Vec<u64>, Box<dyn Error>> {
        let secret_metadata =
        kv2::read_metadata(&*self.read_lock_client()?, &self.config.mount_path, key).await;

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
                &*self.read_lock_client()?,
                &self.config.mount_path,
                key,
                version_result,
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error>)
        }

        pub async fn delete_permanent(&self, key: &str) -> Result<(), Box<dyn Error>> {
            let version = self.versions(key).await?;

            kv2::destroy_versions(
                &*self.read_lock_client()?,
                &self.config.mount_path,
                key,
                version,
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error>)
        }

        pub async fn healthcheck(&self) -> Result<(), Box<dyn Error>> {
            self.read::<HealthCheckData>(self.config.healthcheck_file_path.as_str())
            .await?;
            Ok(())
        }

        pub async fn clear_healthcheck_file(&self) -> Result<(), Box<dyn Error>> {
            let path = self.config.healthcheck_file_path.clone();
            self.delete(&path).await?;
            self.delete_permanent(&path).await
        }

        pub async fn setup_healthcheck_file(&self) -> Result<(), Box<dyn Error>> {
            let data = HealthCheckData {
                data: "health check file".to_string(),
            };
            let path = self.config.healthcheck_file_path.clone();
            self.insert(path.as_str(), data).await?;
            Ok(())
        }

        async fn renew_token(&mut self) -> Result<(), Box<dyn Error>> {
            log::debug!("Renewing Vault token");
            let mut client = self.write_lock_client()?;
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

    type ThreadHandler = Option<(JoinHandle<Result<(), ClientError>>, Sender<()>)>;

    #[async_trait]
    pub trait TokenRenewable {
        fn start_token_renewal(&self) -> Result<ThreadHandler, Box<dyn Error>>;

        fn read_lock(&self) -> Result<RwLockReadGuard<'_, VaultService>, Box<dyn Error>>;

        fn start_token_renew_loop(
            &self,
            auth_info: AuthInfo,
            receiver: Receiver<()>,
        ) -> JoinHandle<()>;

        async fn stop_token_renew_loop(handler: (JoinHandle<Result<(), ClientError>>, Sender<()>));
    }

    #[async_trait]
    impl TokenRenewable for Arc<RwLock<VaultService>> {
        fn start_token_renewal(&self) -> Result<ThreadHandler, Box<dyn Error>> {
            let locked_service = self.read_lock()?;
            if let AuthResult::AuthInfo { auth_info } = locked_service.auth_result {
                drop(locked_service);
                if !auth_info.renewable {
                    return Ok(None);
                }
                let (sender, receiver) = mpsc::channel::<()>(1);
                let handler =
                tokio::spawn(async move { self.start_token_renew_loop(auth_info, receiver) });
                return Ok(Some((handler, sender)));
            } else {
                return Ok(None);
            }
        }

        fn read_lock(&self) -> Result<RwLockReadGuard<'_, VaultService>, Box<dyn Error>> {
            self.read().map_err(|e| Box::new(e) as Box<dyn Error>)
        }

        fn start_token_renew_loop(
            self,
            auth_info: AuthInfo,
            mut receiver: Receiver<()>,
        ) -> JoinHandle<()> {
            let service = Arc::clone(&self);
            tokio::task::spawn( async {
                let time = std::time::Duration::new(auth_info.lease_duration - 5, 0);
                let mut interval = tokio::time::interval(time);
                loop {
                    interval.tick().await;
                    if let Ok(()) = receiver.try_recv() {
                        break;
                    }
                    match service.write() {
                        Ok(mut res) => {
                            while res.renew_token().await.is_err() {
                                log::error!("retring to renew token");
                            }
                        }
                        Err(err) => {
                            log::error!("{}", err);
                        }
                    };
                }
            })
        }

        async fn stop_token_renew_loop(handler: (JoinHandle<Result<(), ClientError>>, Sender<()>)) {
            let (handler, sender) = handler;
            sender.send(()).await;
            handler.abort();
        }
    }


fn start_token_renew_loop(
    service: Arc<RwLock<VaultService>>,
    auth_info: AuthInfo,
    mut receiver: Receiver<()>,
) -> JoinHandle<()> {
    let service_clone = Arc::clone(&service);
    tokio::task::spawn_blocking(  move || {
        let service = Arc::clone(&service).read().unwrap();
        let client = service.client;
        let service_clone_clone = Arc::clone(&service_clone);
        tokio::runtime::Runtime::new().unwrap().block_on( async move {
            let time = std::time::Duration::new(auth_info.lease_duration - 5, 0);
            let mut interval = tokio::time::interval(time);
            loop {
                interval.tick().await;
                if let Ok(()) = receiver.try_recv() {
                    break;
                }
                let mut auth_info = renew_token(client).await;
                while auth_info.is_err() {
                    log::error!("retring to renew token");
                    auth_info = renew_token(client).await;
                }
                let mut w_lock = service_clone_clone.write().unwrap();
                w_lock.auth_result = auth_info.unwrap();
            };
        })
    })
}

async fn renew_token(client: Arc<RwLock<VaultClient>>) -> Result<AuthResult, Box<dyn Error>> {
    log::debug!("Renewing Vault token");
    let mut client = client.write().unwrap();
    match client.renew(None).await {
        Ok(auth_info) => {
            client.set_token(&auth_info.client_token);
            log::info!("Successfully renewed Vault token");
            Ok(AuthResult::auth_info(auth_info))
        }
        Err(err) => {
            log::info!("An error occurred during Vault token renewal\n{}", err);
            Err(Box::new(err))
        }
    }
}