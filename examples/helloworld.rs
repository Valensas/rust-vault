use std::sync::Arc;
use tokio::sync::RwLock;

use serde::{Serialize, Deserialize};
use tokio::{signal::unix::{signal, SignalKind}, select};
use valensas_vault::service::{VaultService, TokenRenewable};

#[derive(Serialize, Deserialize, Clone)]
struct MySpecialToken {
    special_data: String 
}

#[tokio::main]
async fn main() {
    std::env::set_var("VAULT_ADDR", "http://127.0.0.1:8200");
    std::env::set_var("VAULT_DEV_ROOT_TOKEN_ID", "vault_token");
    std::env::set_var("VAULT_TOKEN", "vault_token");
    std::env::set_var("VAULT_AUTH_METHOD", "Token");

    // During construction, service tries create a client and connect to vault server
    let trial_for_connection = VaultService::from_env().await;
    let (vault_service, auth_method) = match trial_for_connection {
        Ok(connected_to_vault) => {
            (Arc::new(RwLock::new(connected_to_vault.0)), connected_to_vault.1)
        },
        Err(err) => {
            panic!("{}", err)
        }
    };
    
    // If the auth info indicates that the token is renewable, begin renewing cycle
    let token_renewal_handlers = match vault_service.start_token_renewal(auth_method) {
        Ok(handler) => {
            handler
        },
        Err(err) => {
            println!("token is not renewable: {}", err);
            return;
        }
    };

    // Do some stuff here
    {
        let my_data = MySpecialToken {
            special_data: "incredibly secret data".to_string()
        };
        
        vault_service.read().await.insert(
            "MySuperToken",
            my_data.clone()
        ).await.unwrap();

        let x: MySpecialToken = vault_service.read().await.read(
            "MySuperToken"
        ).await.unwrap();

        if x.special_data != my_data.special_data {
            println!("inserted data does not match with the saved one");
        }
        else {
            println!("example scenerio succeed");
        }
    };

    // To gracefully shutdown token renewal loop token renewal abortion is needed
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();

    let handler = tokio::task::spawn_blocking(move || {
        tokio::runtime::Runtime
            ::new()
            .unwrap()
            .block_on(async {
                loop {
                    select! {
                        _ = sigterm.recv() => println!("Sigterm receiver"),
                        _ = sigint.recv() => println!("Sigterm receiver"),
                    }
                    break;
                }
            })
    });

    match handler.await {
        Ok(_) => {
            if let Some(token_renewal_handlers) = token_renewal_handlers {
                vault_service.stop_token_renew_loop(token_renewal_handlers).await;
            }
            println!("Vault token renewal cycle shutdown gracefully");
        },
        Err(err) => {
            println!("token renewal thread could not joined to main thread: {}", err);
        }
    }
}