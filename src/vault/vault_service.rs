#![allow(non_snake_case)]
use std::{ io::Read, sync::{ Arc, RwLock } };
use rocket::futures::executor::block_on;
use rustify::clients::reqwest::Client as HTTPClient;
use serde::{ Deserialize, Serialize };
use tokio::task::JoinHandle;
use vaultrs::{
    api::AuthInfo,
    auth::kubernetes,
    client::{ Client, VaultClient, VaultClientSettingsBuilder },
    error::ClientError,
    kv2,
};

use crate::errors::error::VaultError;

use super::vault_params::VaultParams;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HealthCheckData {
    pub data: String,
}

pub struct VaultService {
    pub vault_client: VaultClient,
    vault_params: VaultParams,
    pub vault_auth_info: Option<AuthInfo>,
}

impl std::fmt::Debug for VaultService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultService")
            .field("vault_params", &self.vault_params)
            .field("vault_auth_info", &self.vault_auth_info)
            .finish()
    }
}

impl Clone for VaultService {
    fn clone(&self) -> Self {
        let http_client = HTTPClient {
            http: self.vault_client.http.http.clone(),
            base: self.vault_client.http.base.clone(),
        };
        let client = VaultClient {
            http: http_client,
            middle: self.vault_client.middle.clone(),
            settings: self.vault_client.settings.clone(),
        };
        let auth_info = match &self.vault_auth_info {
            Some(res) => {
                let auth_instance = res;
                Some(AuthInfo {
                    client_token: auth_instance.client_token.clone(),
                    accessor: auth_instance.accessor.clone(),
                    policies: auth_instance.policies.clone(),
                    token_policies: auth_instance.token_policies.clone(),
                    metadata: auth_instance.metadata.clone(),
                    lease_duration: auth_instance.lease_duration.clone(),
                    renewable: auth_instance.renewable.clone(),
                    entity_id: auth_instance.entity_id.clone(),
                    token_type: auth_instance.token_type.clone(),
                    orphan: auth_instance.orphan.clone(),
                })
            }
            None => None,
        };
        Self {
            vault_auth_info: auth_info,
            vault_client: client,
            vault_params: self.vault_params.clone(),
        }
    }
}

impl VaultService {
    pub async fn new(params: VaultParams) -> Result<Self, VaultError> {
        let mut client: VaultClient;
        let mut auth_info: Option<AuthInfo> = None;
        if params.vault_auth_method == "TOKEN" {
            // Create a client
            client = VaultClient::new(
                VaultClientSettingsBuilder::default()
                    .address(params.vault_address.clone())
                    .token(params.vault_token.clone().unwrap())
                    .timeout(Some(params.vault_client_timeout))
                    .build()
                    .unwrap()
            ).unwrap();
            match client.status().await {
                Ok(_) => {}
                Err(err) => {
                    return Err(
                        VaultError::new(
                            format!("Vault could not authenticated with token auth:\n{}", err)
                        )
                    );
                }
            };
        } else {
            let mut token = String::new();
            let mut file = match
                std::fs::File::open(params.clone().vault_token_path.unwrap().as_str())
            {
                Ok(res) => res,
                Err(err) => {
                    return Err(
                        VaultError::new(
                            format!(
                                "File does not exists in given path: {}\n{}",
                                params.vault_token_path.clone().unwrap(),
                                err
                            )
                        )
                    );
                }
            };
            match file.read_to_string(&mut token) {
                Ok(_) => {}
                Err(err) => {
                    log::error!("{}", err);
                }
            }
            client = VaultClient::new(
                VaultClientSettingsBuilder::default()
                    .address(params.vault_address.clone())
                    .timeout(Some(params.vault_client_timeout))
                    .build()
                    .unwrap()
            ).unwrap();
            match
                kubernetes::login(
                    &client,
                    "kubernetes",
                    &params.vault_role_name.clone().unwrap(),
                    &token.trim()
                ).await
            {
                Ok(res) => {
                    client.set_token(&res.client_token);
                    auth_info = Some(res);
                }
                Err(err) => {
                    return Err(
                        VaultError::new(
                            format!("Vault could not authenticated with kubernetes auth:\n{}", err)
                        )
                    );
                }
            }
        }
        Ok(Self {
            vault_auth_info: auth_info,
            vault_client: client,
            vault_params: params,
        })
    }

    pub async fn renewToken(&mut self) {
        log::debug!("vault token renewal began");
        match self.vault_client.renew(None).await {
            Ok(res) => {
                self.vault_client.set_token(&res.client_token);
                self.vault_auth_info = Some(res);
                log::info!("vault token renewal is successfull");
            }
            Err(err) => {
                log::info!("an error occured during token renewal\n{}", err);
            }
        }
    }

    pub async fn insert<T: serde::Serialize>(&self, key: &str, data: T) -> bool {
        kv2::set(&self.vault_client, &self.vault_params.vault_mount_path, key, &data).await.is_ok()
    }

    pub async fn read<'a, T: for<'de> serde::Deserialize<'de>>(
        &self,
        key: &str
    ) -> Result<T, ClientError> {
        kv2::read(&self.vault_client, &self.vault_params.vault_mount_path, key).await
    }

    async fn versions(&self, key: &str) -> Result<Vec<u64>, ClientError> {
        let x = kv2::read_metadata(
            &self.vault_client,
            &self.vault_params.vault_mount_path,
            key
        ).await;
        if x.is_err() {
            return Err(ClientError::FileNotFoundError {
                path: key.to_string(),
            });
        }
        Ok(
            x
                .unwrap()
                .versions.into_iter()
                .map(|x| x.0.parse::<u64>().unwrap())
                .collect()
        )
    }

    pub async fn delete(&self, key: &str) -> Result<bool, ClientError> {
        let version_result = self.versions(key).await;
        if version_result.is_err() {
            return Err(version_result.err().unwrap());
        }
        Ok(
            kv2
                ::delete_versions(
                    &self.vault_client,
                    &self.vault_params.vault_mount_path,
                    key,
                    version_result.ok().unwrap()
                ).await
                .is_err()
        )
    }

    pub async fn permenantly_delete(&self, key: &str) -> Result<bool, ClientError> {
        let version = match self.versions(key).await {
            Ok(version) => version,
            Err(err) => {
                return Err(err);
            }
        };

        match
            kv2::destroy_versions(
                &self.vault_client,
                &self.vault_params.vault_mount_path,
                key,
                version
            ).await
        {
            Ok(_) => Ok(true),
            Err(err) => Err(err),
        }
    }

    pub async fn clearHealthFile(&self) -> Result<bool, VaultError> {
        let path = self.vault_params.vault_healthcheck_file_path.clone();
        let delete = match self.delete(&path).await {
            Ok(_) => Ok(true),
            Err(err) => Err(VaultError::new(format!("{}", err))),
        };
        let perm_delete = match self.permenantly_delete(&path).await {
            Ok(_) => Ok(true),
            Err(err) => Err(VaultError::new(format!("{}", err))),
        };
        if perm_delete.is_ok() && delete.is_ok() {
            delete
        } else {
            let mut perm_err = VaultError::new("".to_string());
            let mut err = VaultError::new("".to_string());
            if perm_delete.is_err() {
                perm_err = perm_delete.unwrap_err();
                log::error!(
                    "an error occured during health file removal:\npermanent delete error: {}",
                    perm_err
                );
            }
            if delete.is_err() {
                err = delete.unwrap_err();
                log::error!("an error occured during health file removal:\ndelete error: {}", err);
            }
            Err(VaultError::new(format!("{}\n{}", perm_err, err)))
        }
    }

    pub async fn setupHealtcheckFile(&self) -> Result<bool, VaultError> {
        let data = HealthCheckData {
            data: "health check file".to_string(),
        };
        let path = self.vault_params.vault_healthcheck_file_path.clone();
        match self.insert(path.as_str(), data).await {
            true => Ok(true),
            false => Err(VaultError::new("vault health file could not be inserted!".to_string())),
        }
    }
}

pub async fn tokenRenewalCycle(
    cloned_vault_service: Arc<RwLock<VaultService>>
) -> Option<JoinHandle<Result<(), VaultError>>> {
    let x: Option<tokio::task::JoinHandle<_>> = match cloned_vault_service.clone().read() {
        Ok(res) => {
            match res.clone().vault_auth_info {
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
                                let cloned_cloned_vault = Arc::clone(&cloned_vault_service);
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
    token_renewal_handler: Option<JoinHandle<Result<(), VaultError>>>
) {
    match token_renewal_handler {
        Some(res) => {
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
        None => {}
    }
}
