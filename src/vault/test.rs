#![allow(non_snake_case)]
#![cfg(test)]

use std::{ thread, time::Duration };

use rustify::errors::ClientError as RustifyClientError;
use serde::{ Deserialize, Serialize };
use serde_json::Value;
use vaultrs::error::ClientError;

use crate::vault::{vault_service::VaultService, vault_params::VaultParams};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct TestData {
    name: String,
}

#[tokio::test]
async fn vault_write_delete_test() {
    let vault_params = &VaultParams::loadEnv();

    let mut vault_service = VaultService::new(vault_params.clone()).await;

    for _ in 0..vault_params.vault_retry_count {
        if vault_service.is_err() {
            log::warn!("could not create vault retrying to login");
            thread::sleep(Duration::from_secs(1));
            vault_service = VaultService::new(vault_params.clone()).await;
        } else {
            break;
        }
    }

    if vault_service.is_err() {
        panic!("{}", vault_service.unwrap_err());
    }

    let vault_service = vault_service.unwrap();

    let inserted_data = TestData {
        name: "trial".to_string(),
    };
    match vault_service.insert("test_1", inserted_data.clone()).await {
        true => {
            match vault_service.read::<TestData>("test_1").await {
                Ok(res) => {
                    assert_eq!(res, inserted_data);
                }
                Err(err) => panic!("{}", err),
            }

            vault_service.delete("test_1").await.unwrap();
            match vault_service.read::<TestData>("test_1").await {
                Ok(_) => panic!("Should be deleted"),
                Err(err) => {
                    if let ClientError::RestClientError { source } = err {
                        if let RustifyClientError::ServerResponseError { code, content } = source {
                            assert_eq!(code, 404);
                            let destroyed: Value = serde_json::from_str(&content.unwrap()).unwrap();
                            if
                                let Value::Bool(is_destroyed) =
                                    destroyed["data"]["metadata"]["destroyed"]
                            {
                                assert!(!is_destroyed);
                                return;
                            }
                        }
                    }
                }
            }
            assert!(false);
        }
        false => { panic!("data could not be inserted") }
    }
}

#[tokio::test]
async fn vault_write_destroy_test() {
    let vault_params = VaultParams::loadEnv();

    let mut vault_service = VaultService::new(vault_params.clone()).await;

    for _ in 0..vault_params.vault_retry_count {
        if vault_service.is_err() {
            log::warn!("could not create vault retrying to login");
            thread::sleep(Duration::from_secs(1));
            vault_service = VaultService::new(vault_params.clone()).await;
        } else {
            break;
        }
    }

    if vault_service.is_err() {
        panic!("{}", vault_service.unwrap_err());
    }

    let vault_service = vault_service.unwrap();

    let inserted_data = TestData {
        name: "trial".to_string(),
    };
    match vault_service.insert("test_2", inserted_data.clone()).await {
        true => {
            match vault_service.read::<TestData>("test_2").await {
                Ok(res) => {
                    assert_eq!(res, inserted_data);
                }
                Err(err) => panic!("{}", err),
            }

            vault_service.permenantly_delete("test_2").await.unwrap();
            match vault_service.read::<TestData>("test_2").await {
                Ok(_) => panic!("Should be deleted"),
                Err(err) => {
                    if let ClientError::RestClientError { source } = err {
                        if let RustifyClientError::ServerResponseError { code, content } = source {
                            assert_eq!(code, 404);
                            let destroyed: Value = serde_json::from_str(&content.unwrap()).unwrap();
                            if
                                let Value::Bool(is_destroyed) =
                                    destroyed["data"]["metadata"]["destroyed"]
                            {
                                assert!(is_destroyed);
                                return;
                            }
                        }
                    }
                }
            }
            assert!(false);
        }
        false => { panic!("data could not be inserted") }
    }
}
