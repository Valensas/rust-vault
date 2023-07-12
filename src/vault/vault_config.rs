#![allow(non_snake_case)]

use duration_string::DurationString;
use std::env;
use std::error;
use std::fmt::{Debug, Display, Formatter};
use std::num::ParseIntError;
use std::str::FromStr;
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum AuthMethod {
    Token,
    Kubernetes,
}

#[derive(Debug, Clone)]
pub struct UnknownAuthMethodError;

impl error::Error for UnknownAuthMethodError {}

impl Display for UnknownAuthMethodError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Env variable: VAULT_AUTH_METHOD is not valid. Possible values: Token, Kubernetes"
        )
    }
}

impl FromStr for AuthMethod {
    type Err = UnknownAuthMethodError;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "Token" => Ok(AuthMethod::Token),
            "Kubernetes" => Ok(AuthMethod::Kubernetes),
            _ => Err(UnknownAuthMethodError),
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
    pub fn loadEnv() -> Result<VaultConfig, Box<dyn error::Error>> {
        let method: Result<AuthMethod, UnknownAuthMethodError> = env::var("VAULT_AUTH_METHOD")
            .unwrap_or_else(|_| String::from("Token"))
            .parse::<AuthMethod>();
        let auth_method = match method {
            Ok(mtd) => mtd,
            Err(err) => {
                log::warn!("Env variable: VAULT_AUTH_METHOD is not valid. Possible values: Token, Kubernetes");
                return Err(err.into());
            }
        };

        let mut token: Option<String> = None;
        let mut role_name: Option<String> = None;
        let mut token_path: Option<String> = None;

        match auth_method {
            AuthMethod::Token => {
                token = match env::var("VAULT_TOKEN") {
                    Ok(token) => Some(token),
                    Err(_) => {
                        log::warn!("vault token must be set for 'Token' authentication");
                        None
                    }
                };
            }
            AuthMethod::Kubernetes => {
                role_name =
                    Some(env::var("VAULT_KUBERNETES_ROLE_NAME").unwrap_or(String::from("client")));
                let path = env::var("VAULT_KUBERNETES_TOKEN_PATH").unwrap_or(String::from(
                    "/var/run/secrets/kubernetes.io/serviceaccount/token",
                ));
                token_path = Some(format!("{}{}", env::current_dir().unwrap().display(), path));
            }
        }
        let address: String =
            env::var("VAULT_ADDR").unwrap_or(String::from("http://localhost:8200"));
        let mount_path: String = env::var("VAULT_MOUNT_PATH").unwrap_or(String::from("secret"));
        let client_timeout_str: String =
            env::var("VAULT_CLIENT_TIMEOUT").unwrap_or(String::from("5s"));
        let client_timeout: Duration = match DurationString::from_string(client_timeout_str) {
            Ok(timeout) => Ok(Duration::from(timeout)),
            Err(err) => {
                log::warn!("Vault client timeout could not be parsed as duration.");
                Err(err)
            }
        }?;

        let healthcheck_file_path: String =
            env::var("VAULT_HEALTH_CHECK_FILE").unwrap_or(String::from("healthcheck_file"));

        let retry_count_result: Result<u16, ParseIntError> = env::var("VAULT_RETRY_COUNT")
            .unwrap_or(String::from("5"))
            .parse::<u16>();

        let retry_count = match retry_count_result {
            Ok(ret_count) => ret_count,
            Err(err) => {
                log::warn!("Env variable: VAULT_RETRY_COUNT is not valid. Type must be the u16.");
                return Err(err.into());
            }
        };

        Ok(VaultConfig {
            auth_method,
            token,
            role_name,
            token_path,
            address,
            mount_path,
            client_timeout,
            healthcheck_file_path,
            retry_count,
        })
    }
}
