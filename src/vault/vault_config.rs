#![allow(non_snake_case)]

use std::str::FromStr;
use std::time::Duration;
use mpc_utils::env::util::Util;

#[derive(Clone, Debug)]
pub enum AuthMethod {
    Token,
    Kubernetes,
}

impl FromStr for AuthMethod {
    type Err = ();

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "Token" => Ok(AuthMethod::Token),
            "Kubernetes" => Ok(AuthMethod::Kubernetes),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultConfig {
    pub auth_method: AuthMethod,
    pub token: Option<String>,
    pub role_name: Option<String>,
    pub token_path: Option<String>,
    pub address: String,
    pub mount_path: String,
    pub client_timeout: Duration,
    pub healthcheck_file_path: String,
    pub retry_count: u16,
}

impl VaultConfig {
    pub fn loadEnv() -> VaultConfig {
        let auth_method: AuthMethod = Util::loadOrDefault("VAULT_AUTH_METHOD", "Token")
            .parse::<AuthMethod>()
            .expect("Env variable: VAULT_AUTH_METHOD is not valid. Possible values: Token, Kubernetes");

        let mut token: Option<String> = None;
        let mut role_name: Option<String> = None;
        let mut token_path: Option<String> = None;

        match auth_method {
            AuthMethod::Token => {
                token = Some(Util::loadOrPanic("VAULT_TOKEN", "vault token must be set for 'Token' authentication"))
            }
            AuthMethod::Kubernetes => {
                role_name = Some(Util::loadOrDefault("VAULT_KUBERNETES_ROLE_NAME", "client"));
                token_path = Some(Util::loadOrDefault("VAULT_KUBERNETES_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"));
                token_path = Some(format!("{}{}", std::env::current_dir().unwrap().display(), token_path.unwrap()));
            }
        }

        let address: String = Util::loadOrDefault("VAULT_ADDR", "http://localhost:8200");
        let mount_path: String = Util::loadOrDefault("VAULT_MOUNT_PATH", "secret");
        let client_timeout_str: String = Util::loadOrDefault("VAULT_CLIENT_TIMEOUT", "5s");
        let client_timeout = Util::strToDuration(client_timeout_str, "Vault client timeout could not be parsed as duration.");

        let healthcheck_file_path: String = Util::loadOrDefault("VAULT_HEALTH_CHECK_FILE", "healthcheck_file");

        let retry_count = Util::loadOrDefault("VAULT_RETRY_COUNT", "5")
            .parse::<u16>()
            .expect("Env variable: VAULT_RETRY_COUNT is not valid. Type must be the u16.");

        return VaultConfig {
            auth_method,
            token,
            role_name,
            token_path,
            address,
            mount_path,
            client_timeout,
            healthcheck_file_path,
            retry_count,
        };
    }
}
