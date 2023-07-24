#![cfg(test)]
use serde::{Deserialize, Serialize};
use std::{thread, time::Duration};

use crate::{config::VaultConfig, service::VaultService};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct TestData {
    name: String,
}

#[tokio::test]
async fn write_delete_test() {
    std::env::set_var("VAULT_ADDR", "http://127.0.0.1:8200");
    std::env::set_var("VAULT_DEV_ROOT_TOKEN_ID", "vault_token");
    std::env::set_var("VAULT_TOKEN", "vault_token");
    std::env::set_var("VAULT_AUTH_METHOD", "Token");

    let config = &VaultConfig::load_env().unwrap();
    let mut service = VaultService::from_env().await;

    for _ in 0..config.0.login_retry_count {
        if service.is_err() {
            log::warn!("could not create vault retrying to login");
            thread::sleep(Duration::from_secs(1));
            service = VaultService::from_env().await;
        } else {
            break;
        }
    }

    if service.is_err() {
        panic!("{}", service.unwrap_err());
    }

    let (service, _) = service.unwrap();

    let inserted_data = TestData {
        name: "trial".to_string(),
    };
    match service.insert("test_1", inserted_data.clone()).await {
        Ok(_) => {
            match service.read::<TestData>("test_1").await {
                Ok(res) => {
                    assert_eq!(res, inserted_data);
                }
                Err(err) => panic!("{}", err),
            }

            service.delete("test_1").await.unwrap();
            match service.read::<TestData>("test_1").await {
                Ok(_) => panic!("Should be deleted"),
                Err(_) => {}
            }
        }
        Err(_) => {
            panic!("data could not be inserted")
        }
    }
}

#[tokio::test]
async fn write_destroy_test() {
    std::env::set_var("VAULT_ADDR", "http://127.0.0.1:8200");
    std::env::set_var("VAULT_DEV_ROOT_TOKEN_ID", "vault_token");
    std::env::set_var("VAULT_TOKEN", "vault_token");
    std::env::set_var("VAULT_AUTH_METHOD", "Token");

    let config = &VaultConfig::load_env().unwrap();
    let mut service = VaultService::from_env().await;

    for _ in 0..config.0.login_retry_count {
        if service.is_err() {
            log::warn!("could not create vault retrying to login");
            thread::sleep(Duration::from_secs(1));
            service = VaultService::from_env().await;
        } else {
            break;
        }
    }

    if service.is_err() {
        panic!("{}", service.unwrap_err());
    }

    let (service, _) = service.unwrap();

    let inserted_data = TestData {
        name: "trial".to_string(),
    };
    match service.insert("test_2", inserted_data.clone()).await {
        Ok(_) => {
            match service.read::<TestData>("test_2").await {
                Ok(res) => {
                    assert_eq!(res, inserted_data);
                }
                Err(err) => panic!("{}", err),
            }

            service.delete_permanent("test_2").await.unwrap();
            match service.read::<TestData>("test_2").await {
                Ok(_) => panic!("Should be deleted"),
                Err(_) => {}
            }
        }
        Err(_) => {
            panic!("data could not be inserted")
        }
    }
}
