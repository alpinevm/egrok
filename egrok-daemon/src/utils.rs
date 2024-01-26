use std::fmt::format;
use std::io::BufReader;
use std::println;

use crate::prelude::*;
use isahc::{self, AsyncReadResponseExt};
use serde_json::{json, Value};
use tokio::io::Lines;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, BufReader as AsyncBufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::time::{timeout, Duration};

use form_urlencoded;

pub async fn ngrok_daemon_watcher(
    lines: &mut Lines<AsyncBufReader<ChildStdout>>,
    log_passthrough: bool,
    return_on_start: Option<bool>,
) -> Result<()> {
    while let Some(line) = lines.next_line().await? {
        if return_on_start.unwrap_or(false) && line.contains("started tunnel") {
            break;
        }
        if line.contains("lvl=eror") {
            return Err(Error::Generic(format!(
                "Ngrok process threw an error: {line:}"
            )));
        }

        if log_passthrough {
            println!("{}", line);
        }
    }
    Ok(())
}

pub async fn get_tunnel_address(ngrok_url: &str) -> StdResult<String, Box<dyn StdError>> {
    let response_result = timeout(Duration::from_secs(5), isahc::get_async(ngrok_url)).await?;

    match response_result {
        Ok(mut response) => {
            let res: Value = response.json().await?;
            Ok(res["tunnels"][0]["public_url"].to_string())
        }
        Err(e) => Err(e.into()),
    }
}

pub async fn publish_proxy_location(
    storage_key: &str,
    encrypted_url: &str,
) -> StdResult<String, Box<dyn StdError>> {
    let url_encoded_data: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("data", encrypted_url)
        .finish();

    isahc::get_async(format!(
        "https://dweet.io/dweet/for/{}?{}",
        &storage_key, url_encoded_data
    ))
    .await?;
    Ok(format!(
        "https://dweet.io/get/latest/dweet/for/{}",
        &storage_key
    ))
}
