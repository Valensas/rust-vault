//! This library provides a convenient interface for interacting with Vault.
//! It allows authentication, secret management, and token renewal.
//!
//! ## Installation
//! Add the following to your `Cargo.toml` file:
//! ```toml
//! [dependencies]
//! valensas-vault = "0.2.0"
//! ```
//!
//! ## Usage
//! You should define following environment variables to configure Vault.
//!```yaml
//! VAULT_ADDR: "http://localhost:8200"
//! VAULT_MOUNT_PATH: secret
//! VAULT_CLIENT_TIMEOUT: 5s
//! VAULT_HEALTH_CHECK_FILE: healthcheck_file
//! VAULT_RETRY_COUNT: 5
//! ```
//!
//! For Kubernetes Configuration:
//! ```yaml
//! VAULT_AUTH_METHOD: Kubernetes
//! VAULT_KUBERNETES_ROLE_NAME: client
//! VAULT_KUBERNETES_TOKEN_PATH: /var/run/secrets/kubernetes.io/serviceaccount/token
//! ```
//!
//! For Token Configuration:
//! ```yaml
//! VAULT_AUTH_METHOD: Token
//! VAULT_TOKEN: token
//! ```
//! Given values are default values of the variables. Make sure to replace the variable with your own variables for Vault configuration.
//! VAULT_AUTH_METHOD value can be either Token or Kubernetes.
//! ```rust
//! use std::time::Duration;
//! use valensas_vault::vault::vault_service::{HealthCheckData, VaultService};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
//! struct TestData {
//!     name: String,
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     // Initialize the Vault service
//!     let vault_service = VaultService::new().await.unwrap();
//!
//!     // Write a secret to Vault
//!     let secret_key = "my-new-secret-key";
//!     let secret_value = TestData {
//!         name: "data".to_string(),
//!     };
//!     vault_service.insert(secret_key, secret_value).await.unwrap();
//!     println!("Secret inserted successfully.");
//!
//!     // Read a secret from Vault
//!     let value = vault_service.read::<TestData>(secret_key).await.unwrap();
//!     println!("Secret read successfully.");
//! }
//! ```
//!
//! Token renewal:
//!
//!```rust
//! use std::time::Duration;
//! use valensas_vault::vault::vault_service::{token_renewal, token_renewal_abortion, VaultService};
//! use tokio::sync::RwLock;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Initialize the Vault service
//!     let vault_service = VaultService::new().await.unwrap();
//!
//!     let vault_service = Arc::new(RwLock::new(vault_service));
//!
//!     // Start token renewal
//!     let handler = token_renewal(vault_service);
//!
//!     // Perform some operations...
//!     // ...
//!
//!     // Stop token renewal
//!     // handler may be none in case if auth method is Kubernetes
//!     if let Some((token_renewal_handle, sender)) = handler {
//!         token_renewal_abortion((token_renewal_handle, sender));
//!     }
//! }
//! ```
pub mod config;
pub mod service;
pub mod auth;
