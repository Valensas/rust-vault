/// This library provides a convenient interface for interacting with Vault.
/// It allows authentication, secret management, and token renewal.
///
/// ## Installation
/// Add the following to your `Cargo.toml` file:
/// ```toml
/// [dependencies]
/// valensas_vault = "0.1.0"
/// ```
///
/// ## Usage
///
/// ```rust
/// use std::time::Duration;
/// use mpc_vault::vault::vault_params::VaultParams;
/// use mpc_vault::vault::vault_service::{HealthCheckData, VaultService};
///
/// async fn main() {
///     // Create Vault parameters with authentication method and token
///     let vault_params = VaultParams {
///         vault_auth_method: "token".to_string(),
///         vault_token: Option::from("my-auth-token".to_string()),
///         vault_role_name: None,
///         vault_token_path: None,
///         vault_address: "http://localhost:8200".to_string(),
///         vault_mount_path: "secret".to_string(),
///         vault_client_timeout: Duration::from_secs(5),
///         vault_healthcheck_file_path: "healthcheck_file".to_string(),
///         vault_retry_count: 5
///     };
///
///     // Initialize the Vault service
///     let vault_service = VaultService::new(vault_params).await.unwrap();
///
///     // Read a secret from Vault
///     let secret_value = vault_service.clone().read::<HealthCheckData>(vault_params.vault_healthcheck_file_path.as_str()).await;
///     println!("Secret value: {}", secret_value.unwrap());
///
///     // Write a secret to Vault
///     let secret_key = "my-new-secret-key";
///     let secret_value = "my-new-secret-value";
///     vault_service.insert(secret_key, secret_value).await;
///     println!("Secret inserted successfully.");
/// }
/// ```
///
/// Token renewal:
///
/// ```rust
/// use std::time::Duration;
/// use mpc_vault::vault::vault_params::VaultParams;
/// use mpc_vault::vault::vault_service::{tokenRenewalCycle, tokenRenewalAbortion, VaultService};
///
/// // Create Vault parameters with authentication method and token
/// let vault_params = VaultParams {
///     vault_auth_method: "token".to_string(),
///     vault_token: Option::from("my-auth-token".to_string()),
///     vault_role_name: None,
///     vault_token_path: None,
///     vault_address: "http://localhost:8200".to_string(),
///     vault_mount_path: "secret".to_string(),
///     vault_client_timeout: Duration::from_secs(5),
///     vault_healthcheck_file_path: "healthcheck_file".to_string(),
///     vault_retry_count: 5
/// };
///
/// // Initialize the Vault service
/// let mut vault_service = VaultService::new(vault_params);
///
/// // Start token renewal in the background
/// let token_renewal_handle = tokenRenewalCycle(vault_service);
///
/// // Perform some operations...
/// // ...
///
/// // Stop token renewal
/// vault_service.tokenRenewalAbortion(token_renewal_handle);
/// ```

pub mod vault;
pub mod errors;