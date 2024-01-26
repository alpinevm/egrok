use crate::prelude::*;

mod error;
mod prelude;
mod utils;

use std::{fmt, println, todo};

use egrok_lib::{config, simple_encryption};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader as AsyncBufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout, Duration};

use clap::{Parser, Subcommand};
use config::Args;
use utils::*;

#[derive(Debug)]
struct EgrokDaemon {
    tcp_port: String,
    log_passthrough: bool,
    ngrok_process: Option<Child>,
}

impl EgrokDaemon {
    pub fn new(tcp_port: &str, log_passthrough: bool) -> Self {
        EgrokDaemon {
            ngrok_process: None,
            tcp_port: tcp_port.to_string(),
            log_passthrough,
        }
    }

    async fn refresh_ngrok_connection(&mut self) -> Result<()> {
        self.ngrok_process = Some(
            Command::new("ngrok")
                .args(&["tcp", &self.tcp_port, "--log", "stdout"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        Ok(())
    }
}

#[tokio::main]
async fn main() -> StdResult<(), Box<dyn StdError>> {
    let args = config::Args::parse();
    match &args.config {
        Some(config::ArgConfig::Config { guid, pwd }) => {
            // Handle config setup
            config::create(&args.config_location, &guid, &pwd)
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
            println!("Starting egrokd...");
            loop {
                let mut daemon = EgrokDaemon::new(&args.tcp_port, args.log_passthrough);
                daemon.refresh_ngrok_connection().await?;
                println!("Ngrok process spawned, waiting for tunnel...");
                if let Some(mut child) = daemon.ngrok_process {
                    let mut line_buffer = AsyncBufReader::new(child.stdout.take().unwrap()).lines();
                    utils::ngrok_daemon_watcher(
                        &mut line_buffer,
                        daemon.log_passthrough.clone(),
                        Some(true), // when true this exits when logs say tunnel is online
                    )
                    .await?;
                    let tcp_address =
                        utils::get_tunnel_address("http://127.0.0.1:4040/api/tunnels").await?;

                    println!("Remote TCP Proxy: {}", &tcp_address);
                    let encoded_cipherstr =
                        simple_encryption::encrypt(&broadcast_config.pwd, &tcp_address)?;

                    let dweet_url =
                        publish_proxy_location(&broadcast_config.guid, &encoded_cipherstr).await?;
                    println!("Published proxy location to: {}", dweet_url);

                    // Exits (an error) when ngrok process throws an error
                    match utils::ngrok_daemon_watcher(
                        &mut line_buffer,
                        daemon.log_passthrough.clone(),
                        None, // when none/false this exits when logs say tunnel is down
                    )
                    .await
                    {
                        Ok(_watcher_response) => {}
                        Err(error) => {
                            // Just display it
                            println!("{}", error);
                        }
                    }
                    // clean up
                    child.kill().await?;
                }
                println!("Restarting ngrok process...");
            }
        }
    }
    Ok(())
}
