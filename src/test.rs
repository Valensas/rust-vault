#![cfg(test)]
use serde::{Deserialize, Serialize};

use crate::service::VaultService;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct TestData {
    name: String,
}

#[tokio::test]
async fn write_delete_test() {
    let (service, _) = VaultService::from_env().await.unwrap();
    let service = service.read().await;

    let test_data = TestData {
        name: "trial".to_string(),
    };
    service.insert("test_1", test_data.clone()).await.expect("Failed to insert data");
    let res = service.read::<TestData>("test_1").await.expect("Failed to read data");
    assert_eq!(res, test_data);
}

#[tokio::test]
async fn write_destroy_test() {
    let (service, _) = VaultService::from_env().await.unwrap();
    let service = service.read().await;

    let test_data = TestData {
        name: "trial".to_string(),
    };
    service.insert("test_2", test_data.clone()).await.expect("Failed to insert data");
    let res = service.read::<TestData>("test_2").await.expect("Failed to read data");
    assert_eq!(res, test_data);


    service.delete_permanent("test_2").await.expect("Failed to permanent delete");
    assert!(service.read::<TestData>("test_2").await.is_err());
}
