use crate::auth::method::AuthMethod;
use duration_string::DurationString;
use std::env;
use std::error;
use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::num::ParseIntError;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use crate::auth::kubernetes::KubernetesAuth;
use crate::auth::token::TokenAuth;

#[derive(Debug)]
enum ConfigError {
    MissingToken,
    UnknownAuthMethod(String),
    InvalidTimeoutDuration(String, String),
    InvalidLoginRetryCount(String, ParseIntError),
    KubernetesAuthError(io::Error),
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingToken => write!(f, "VAULT_TOKEN must be set for token authentication"),
            Self::UnknownAuthMethod(m) => write!(f, "Auth method {} is not valid. Possible values: Token, Kubernetes", m),
            Self::InvalidTimeoutDuration(v, err) => write!(f, "Error parsing VAULT_CLIENT_TIMEOUT `{}': {}", v, err),
            Self::InvalidLoginRetryCount(v, err) => write!(f, "Error parsing VAULT_LOGIN_RETRY_COUNT `{}': {}", v, err),
            Self::KubernetesAuthError(err) => write!(f, "Unable to initialize Kubernetes authentication: {}", err),
        }
    }
}

impl error::Error for ConfigError {}

#[derive(Clone, Debug)]
pub struct VaultConfig {
    pub auth_method: Arc<RwLock<dyn AuthMethod>>,
    pub address: String,
    pub mount_path: String,
    pub client_timeout: Duration,
    pub healthcheck_file_path: String,
    pub login_retry_count: u16,
}

impl VaultConfig {
    pub fn load_env() -> Result<Self, ConfigError> {
        let method = env::var("VAULT_AUTH_METHOD")
            .unwrap_or_else(|_| String::from("Token"));

        let auth_method: Arc<dyn AuthMethod> = match method.as_str() {
            "Token" => {
                match env::var("VAULT_TOKEN") {
                    Ok(token) => Arc::new(TokenAuth::new(token)),
                    Err(_) => return Err(ConfigError::MissingToken)
                }
            }
            "Kubernetes" => {
                let sa_token_path = env::var("VAULT_KUBERNETES_TOKEN_PATH").ok();
                let auth_mount_path = env::var("VAULT_AUTH_MOUNT_PATH").ok();
                match KubernetesAuth::new(auth_mount_path, sa_token_path) {
                    Ok(kAuth) => Arc::new(kAuth),
                    Err(err) => return Err(ConfigError::KubernetesAuthError(err))
                }
            }
            method => return Err(ConfigError::UnknownAuthMethod(method.to_string()))
        };

        let address = env::var("VAULT_ADDR").unwrap_or(String::from("http://localhost:8200"));
        let mount_path = env::var("VAULT_MOUNT_PATH").unwrap_or(String::from("secret"));
        let client_timeout = Self::get_client_timeout()?;

        let healthcheck_file_path: String = env::var("VAULT_HEALTH_CHECK_FILE").unwrap_or(String::from("healthcheck_file"));

        let retry_count = Self::get_login_retry_count()?;

        Ok(VaultConfig {
            auth_method,
            address,
            mount_path,
            client_timeout,
            healthcheck_file_path,
            login_retry_count: retry_count,
        })
    }

    fn get_client_timeout() -> Result<Duration, ConfigError> {
        let client_timeout_str =env::var("VAULT_CLIENT_TIMEOUT").unwrap_or(String::from("5s"));

        match DurationString::from_string(client_timeout_str) {
            Ok(timeout) => Ok(Duration::from(timeout)),
            Err(err) => Err(ConfigError::InvalidTimeoutDuration(client_timeout_str, err))
        }
    }

    fn get_login_retry_count() -> Result<u16, ConfigError> {
        let retry_count_str= env::var("VAULT_LOGIN_RETRY_COUNT")
            .unwrap_or(String::from("5"));

        match retry_count_str.parse::<u16>() {
            Ok(retry_count) => Ok(retry_count),
            Err(err) => Err(ConfigError::InvalidLoginRetryCount(retry_count_str, err))
        }
    }



}
