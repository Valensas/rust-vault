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
/// You should define following environment variables to configure Vault.
///
/// VAULT_ADDR: default "http://localhost:8200"
/// VAULT_MOUNT_PATH: default secret
/// VAULT_CLIENT_TIMEOUT: default 5s
/// VAULT_HEALTH_CHECK_FILE: default healthcheck_file
/// VAULT_RETRY_COUNT: default 5
///
/// For Kubernetes Configuration:
/// VAULT_AUTH_METHOD: Kubernetes
/// VAULT_KUBERNETES_ROLE_NAME: default client
/// VAULT_KUBERNETES_TOKEN_PATH: default /var/run/secrets/kubernetes.io/serviceaccount/token
/// For Token Configuration:
/// VAULT_AUTH_METHOD: Token
/// VAULT_TOKEN: token to authenticate vault
/// ```rust
/// use std::time::Duration;
/// use valensas_vault::vault::vault_service::{HealthCheckData, VaultService, VaultParams};
///
/// async fn main() {
///     // Initialize the Vault service
///     let vault_service = VaultService::new().await.unwrap();
///
///     // Write a secret to Vault
///     let secret_key = "my-new-secret-key";
///     let secret_value = TestData {
///         name: "data".to_string(),
///     };
///     vault_service.insert(secret_key, secret_value).await;
///     println!("Secret inserted successfully.");
///
///     // Read a secret from Vault
///     let value = vault_service.read::<TestData>(secret_key).await.unwrap();
///     println!("Secret read successfully.");
/// }
/// ```
///
/// Token renewal:
///
/// ```rust
/// use std::time::Duration;
/// use valensas_vault::vault::vault_service::{tokenRenewalCycle, tokenRenewalAbortion, VaultService};
/// // Initialize the Vault service
/// let mut vault_service = VaultService::new();
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