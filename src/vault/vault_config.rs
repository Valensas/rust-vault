#![allow(non_snake_case)]

use std::env;
use std::str::FromStr;
use std::time::Duration;
use duration_string::DurationString;

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
        let auth_method: AuthMethod = env::var("VAULT_AUTH_METHOD").unwrap_or(String::from("Token"))
            .parse::<AuthMethod>()
            .expect("Env variable: VAULT_AUTH_METHOD is not valid. Possible values: Token, Kubernetes");

        let mut token: Option<String> = None;
        let mut role_name: Option<String> = None;
        let mut token_path: Option<String> = None;

        match auth_method {
            AuthMethod::Token => {
                token = Some(env::var("VAULT_TOKEN").expect("vault token must be set for 'Token' authentication"))
            }
            AuthMethod::Kubernetes => {
                role_name = Some(env::var("VAULT_KUBERNETES_ROLE_NAME").unwrap_or(String::from("client")));
                token_path = Some(env::var("VAULT_KUBERNETES_TOKEN_PATH").unwrap_or(String::from("/var/run/secrets/kubernetes.io/serviceaccount/token")));
                token_path = Some(format!("{}{}", env::current_dir().unwrap().display(), token_path.unwrap()));
            }
        }
        let address: String = env::var("VAULT_ADDR").unwrap_or(String::from("http://localhost:8200"));
        let mount_path: String = env::var("VAULT_MOUNT_PATH").unwrap_or(String::from("secret"));
        let client_timeout_str: String = env::var("VAULT_CLIENT_TIMEOUT").unwrap_or(String::from("5s"));
        let client_timeout = DurationString::from_string(client_timeout_str).expect("Vault client timeout could not be parsed as duration.").into();

        let healthcheck_file_path: String = env::var("VAULT_HEALTH_CHECK_FILE").unwrap_or(String::from("healthcheck_file"));

        let retry_count: u16 = env::var("VAULT_RETRY_COUNT").unwrap_or(String::from("5"))
            .parse::<u16>()
            .expect("Env variable: VAULT_RETRY_COUNT is not valid. Type must be the u16.");

        VaultConfig {
            auth_method,
            token,
            role_name,
            token_path,
            address,
            mount_path,
            client_timeout,
            healthcheck_file_path,
            retry_count,
        }
    }
}
