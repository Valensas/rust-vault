//! This library provides a convenient interface for interacting with Vault.
//! It allows authentication, secret management, and token renewal.
//!
//! ## Installation
//! Add the following to your `Cargo.toml` file:
//! ```toml
//! [dependencies]
//! valensas-vault = "0.2.1"
//! ```
//!
//! ## Features
//!
//! Only operations on a KV v2 secret engine are supported. Authentication can be performed using
//! token or Kubernetes authentication.
//!
//! ## Usage
//!
//! ### Manual configuration
//!
//! Create a VaultConfig and AuthMethod to your needs:
//!
//! ```rust
//!  let config = VaultConfig {
//!      address: "http://localhost:8200".to_string(),
//!      mount_path: "asd".to_string(),
//!      client_timeout: std::time::Duration::from_secs(10),
//!      healthcheck_file_path: "/healthcheck".to_string(),
//!      login_retry_count: 10,
//!  };
//!  let auth_method: Arc<RwLock<dyn AuthMethod>> = Arc::new(RwLock::new(TokenAuth::new("some_token".to_string())));
//! ```
//!
//! Create the VaultService from the config and auth method:
//!
//! ```rust
//! let vault_service = VaultService::new(config, Arc::clone(&auth_method)).await.unwrap();
//! ```
//!
//! ### Environment configuration
//!
//! The following environment variables are supported to configure the VaultService:
//!
//!```yaml
//! VAULT_ADDR: "http://localhost:8200"
//! VAULT_MOUNT_PATH: secret
//! VAULT_HEALTH_CHECK_FILE: healthcheck_file
//! VAULT_CLIENT_TIMEOUT: 5s
//! VAULT_LOGIN_RETRY_COUNT: 5
//! ```
//!
//! For Kubernetes Authentication:
//! ```yaml
//! VAULT_AUTH_METHOD: Kubernetes
//! VAULT_KUBERNETES_TOKEN_PATH: /var/run/secrets/kubernetes.io/serviceaccount/token
//! ```
//!
//! For Token Authentication:
//! ```yaml
//! VAULT_AUTH_METHOD: Token
//! VAULT_TOKEN: vault_token
//! ```
//! Given values are default values of the variables. Make sure to replace the variable with your own variables for Vault configuration.
//!
//! ### Sample ussage
//!
//! ```rust
//! use std::time::Duration;
//! use valensas_vault::service::{HealthCheckData, VaultService};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
//! struct TestData {
//!     name: String,
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let (vault_service, _auth_method) = VaultService::from_env().await.unwrap();
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
//! use valensas_vault::service::{VaultService, TokenRenewable};
//! use tokio::sync::RwLock;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Initialize the Vault service
//!     let (vault_service, auth_method) = VaultService::from_env().await.unwrap();
//!
//!     let vault_service = Arc::new(RwLock::new(vault_service));
//!
//!     // Start token renewal
//!     let handler = vault_service.start_token_renewal(auth_method);
//!
//!     // Perform some operations...
//!     // ...
//!
//!     // Stop token renewal
//!     // handler may be none in case if auth method is Kubernetes
//!     if let Ok(Some(token_renewal_handler)) = handler {
//!         vault_service.stop_token_renew_loop(token_renewal_handler).await;
//!     }
//! }
//! ```
pub mod config;
pub mod service;
pub mod auth;
mod test;