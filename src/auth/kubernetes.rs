use crate::auth::method::AuthMethod;

use std::{error::Error, sync::Arc, fs};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use tokio::sync::RwLock;
use base64::Engine;
use vaultrs::{
    auth::kubernetes,
    client::VaultClient,
    client::Client
};

use super::method::AuthResult;

#[derive(Serialize, Deserialize)]
struct NameUUID {
    name: String,
    #[serde(rename = "uid")]
    uuid: String
}

#[derive(Serialize, Deserialize)]
struct KubernetesIO {
    serviceaccount: NameUUID
}

#[derive(Serialize, Deserialize)]
struct K8infos {
    #[serde(rename = "kubernetes.io")]
    kubernetes_io: KubernetesIO
}

#[derive(Debug)]
pub struct KubernetesAuth {
    mount: String,
    role: String,
    token: String
}

impl KubernetesAuth {
    pub fn new(mount: Option<String>, sa_token_path: Option<String>) -> Result<Self, Box<dyn Error>> {
        let token = fs::read_to_string(sa_token_path.unwrap_or("/var/run/kubernetes.io/serviceaccount/token".to_string()))?;
        
        let encoded_k8_infos = token.split('.')
            .collect::<Vec<&str>>()
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>();
        
        let encoded_k8_infos = encoded_k8_infos
            .get(1)
            .unwrap();

        let mut decoded_k8_infos: Vec<u8> = Vec::new();
        
        base64::engine::GeneralPurpose::new(&base64::alphabet::URL_SAFE, base64::engine::general_purpose::NO_PAD)
            .decode_vec(encoded_k8_infos.as_bytes(), &mut decoded_k8_infos)?;

        let json_k8_infos = String::from_utf8(decoded_k8_infos)?;

        let k8infos = serde_json::from_str::<K8infos>(&json_k8_infos)?;

        Ok(Self {
            mount: mount.unwrap_or("kubernetes".to_string()),
            token,
            role: k8infos.kubernetes_io.serviceaccount.name
        })
    }
}

#[async_trait]
impl AuthMethod for KubernetesAuth {
    async fn authenticate(&self, client: Arc<RwLock<VaultClient>>) -> Result<AuthResult, Box<dyn Error>> {
        let client_infos = client.clone();
        let mount = self.mount.clone();
        let role = self.role.clone();
        let token = self.token.clone();
        let auth_info = tokio::task::spawn_blocking(move || {
            let client_infos = Arc::clone(&client_infos);
            tokio::runtime::Runtime::new().unwrap()
                .block_on(async {
                    let r_lock = client_infos.read().await;
                    let vault_client = &*r_lock;
                    kubernetes::login(
                        vault_client,
                        &mount,
                        &role,
                        &token,
                    ).await
                })
        }).await??;
        let mut client_lock = client.write().await;
        client_lock.set_token(&auth_info.client_token);
        Ok(AuthResult::auth_info(auth_info))
    }
}
