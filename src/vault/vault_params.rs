#![allow(non_snake_case)]
use std::time::Duration;
use mpc_utils::env::util::Util;

#[derive(Clone, Debug)]
pub struct VaultParams {
    pub vault_auth_method: String,
    pub vault_token: Option<String>,
    pub vault_role_name: Option<String>,
    pub vault_token_path: Option<String>,
    pub vault_address: String,
    pub vault_mount_path: String,
    pub vault_client_timeout: Duration,
    pub vault_healthcheck_file_path: String,
    pub vault_retry_count: u16,
}

impl VaultParams {
    pub fn loadEnv() -> VaultParams {
        // Vault Authentication
        let mut vault_token: Option<String> = None;
        let mut vault_role_name: Option<String> = None;
        let mut vault_token_path: Option<String> = None;
        let vault_auth_method: String = Util::loadOrDefault("VAULT_AUTH_METHOD", "KUBERNETES");
        if vault_auth_method == "TOKEN" {
            vault_token = Some(
                Util::loadOrPanic("VAULT_TOKEN", "vault token must be set for token authentication")
            );
        } else if vault_auth_method == "KUBERNETES" {
            vault_role_name = Some(Util::loadOrDefault("VAULT_KUBERNETES_ROLE_NAME", "client"));
            vault_token_path = Some(
                Util::loadOrDefault(
                    "VAULT_KUBERNETES_TOKEN_PATH",
                    "/var/run/secrets/kubernetes.io/serviceaccount/token"
                )
            );
            vault_token_path = Some(
                format!(
                    "{}{}",
                    std::env::current_dir().unwrap().display(),
                    vault_token_path.unwrap()
                )
            );
        } else {
            panic!("Vault auth method must be \"TOKEN\" or \"KUBERNETES\".");
        }

        //Vault Configurations
        let vault_address: String = Util::loadOrDefault("VAULT_ADDR", "http://localhost:8200");
        let vault_mount_path: String = Util::loadOrDefault("VAULT_MONTH_PATH", "secret");
        let str_vault_timeout: String = Util::loadOrDefault("VAULT_CLIENT_TIMEOUT", "5s");
        let vault_client_timeout: Duration = Util::strToDuration(
            str_vault_timeout,
            "Vault client timeout could not be parsed as duration."
        );
        let vault_healthcheck_file_path: String = Util::loadOrDefault(
            "VAULT_HEALTH_CHECK_FILE",
            "healthcheck_file"
        );

        let vault_retry_count = Util::loadOrDefault("VAULT_RETRY_COUNT", "5")
            .parse::<u16>()
            .expect("env value: vault retry count is not valid");

        return VaultParams {
            vault_auth_method,
            vault_token,
            vault_role_name,
            vault_token_path,
            vault_address,
            vault_mount_path,
            vault_client_timeout,
            vault_healthcheck_file_path,
            vault_retry_count,
        };
    }
}
