use std::{println, todo};

use crate::prelude::*;

mod error;
mod prelude;

use clap::{Parser, Subcommand};
use egrok_lib::*;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader as AsyncBufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout, Duration};

use isahc::{self, AsyncReadResponseExt};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct ApiResponse {
    this: String,
    with: ApiResponseData,
    #[serde(skip_serializing_if = "Option::is_none")]
    because: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum ApiResponseData {
    Success(Vec<Dweet>),
    Failure(i32),
}

#[derive(Serialize, Deserialize, Debug)]
struct Dweet {
    thing: String,
    created: String,
    content: Content,
}

#[derive(Serialize, Deserialize, Debug)]
struct Content {
    data: String,
}

async fn get_encrypted_proxy(guid: &str) -> StdResult<String, Box<dyn StdError>> {
    let response: ApiResponse =
        (isahc::get_async(format!("https://dweet.io/get/latest/dweet/for/{}", guid)).await?)
            .json()
            .await?;
    match response.with {
        ApiResponseData::Success(dweets) => Ok(dweets
            .get(0)
            .ok_or_else(|| {
                Box::new(Error::Generic(
                    "Dweet didn't return anything at that guid".to_string(),
                )) as Box<dyn StdError>
            })?
            .content
            .data
            .to_string()),
        ApiResponseData::Failure(fail_code) => Err(Box::new(Error::Generic(format!(
            "Dweet responded with code: {}, and reason {}",
            fail_code,
            response.because.unwrap_or("None".to_string())
        ))) as Box<dyn StdError>),
    }
}

#[tokio::main]
async fn main() -> StdResult<(), Box<dyn StdError>> {
    let args = config::Args::parse();
    match &args.config {
        Some(config::ArgConfig::Config { guid, pwd }) => {
            // Handle config setup
            config::create(&args.config_location, guid, pwd)
                .await
                .map_err(|e| error::Error::Generic(format!("Error creating config: {}", e)))?;
            println!("Config stored at {}", &args.config_location);
        }
        None => {
            // Handle main functionality
            let broadcast_config = config::get(&args.config_location).await.map_err(|e| {
                Error::Generic(format!(
                    "Error handling config, create with `egrokd create` if you haven't already {}",
                    e.to_string()
                ))
            })?;
            let encoded_encrypted_proxy_str = get_encrypted_proxy(&broadcast_config.guid).await?;
            // println!("Encoded proxy: {:?}", &encoded_encrypted_proxy_str.to_string().as_bytes());
            let proxy =
                simple_encryption::decrypt(&broadcast_config.pwd, &encoded_encrypted_proxy_str)?;
            println!("Proxy Address: {}", &proxy);
        }
    }
    Ok(())
}
