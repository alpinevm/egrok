pub mod config {
    use clap::{Parser, Subcommand};
    use serde::Deserialize;
    use std::format;
    use std::path::PathBuf;
    use std::{error::Error, println};
    use tokio::{fs, io};

    /// egrokd: A simple ngrok tcp proxy auto restarter (daemon)
    #[derive(Parser, Debug)]
    #[command(version, about, long_about = None)]
    pub struct Args {
        /// TCP Port to proxy into
        #[arg(short, long, default_value_t = String::from("22"))]
        pub tcp_port: String,

        /// Bubble up ngrok logs to stdout
        #[arg(short, long, default_value_t = false)]
        pub log_passthrough: bool,

        /// Location of egrokd config file
        #[arg(short, long, default_value_t = String::from("~/.egrokd"))]
        pub config_location: String,

        #[command(subcommand)]
        pub config: Option<ArgConfig>,
    }

    #[derive(Subcommand, Debug)]
    pub enum ArgConfig {
        /// Set configuration parameters
        Config {
            /// Set guid in config (for broadcasting)
            #[arg(short, long)]
            guid: String,

            /// Set encryption password in config (for broadcasting)
            #[arg(short, long)]
            pwd: String,
        },
    }

    #[derive(Deserialize)]
    pub struct Config {
        pub guid: String,
        pub pwd: String,
    }

    async fn path_normalizer(file_loc: &str) -> Result<String, Box<dyn Error>> {
        let file_path = if file_loc.starts_with("~") {
            match dirs::home_dir() {
                Some(mut path) => {
                    path.push(&file_loc[2..]); // Skip the "~/" part
                    path
                }
                None => PathBuf::from(file_loc),
            }
        } else {
            PathBuf::from(file_loc)
        };

        Ok(file_path
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid file path"))?
            .to_string())
    }

    pub async fn get(file_loc: &str) -> Result<Config, Box<dyn Error>> {
        let contents = fs::read_to_string(path_normalizer(file_loc).await?).await?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub async fn create(file_loc: &str, guid: &str, pwd: &str) -> Result<(), Box<dyn Error>> {
        let file_path_str = path_normalizer(file_loc).await?;

        if fs::File::open(&file_path_str).await.is_err() {
            fs::File::create(&file_path_str).await?;
        }
        fs::write(
            &file_path_str,
            format!("guid = \"{}\"\npwd = \"{}\"", guid, pwd),
        )
        .await?;
        Ok(())
    }
}

pub mod simple_encryption {

    use std::println;
    use std::time::Instant;

    use aes_gcm::aead::consts::U32;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{
        aead::{Aead, KeyInit, OsRng},
        Aes256Gcm, Nonce,
    };
    use base64::prelude::*;
    use rand::RngCore;
    use scrypt::{
        password_hash::{PasswordHasher, SaltString},
        Scrypt,
    };

    fn derive_key(password: &str, salt: &SaltString) -> Result<GenericArray<u8, U32>, String> {
        let password_hash = Scrypt
            .hash_password(password.as_bytes(), salt)
            .map_err(|e| e.to_string())?;

        match password_hash.hash {
            Some(hash) => {
                let bytes = hash.as_bytes().to_owned();
                let key_array: Result<[u8; 32], _> = bytes.try_into();
                key_array
                    .map(GenericArray::from)
                    .map_err(|_| "Key derivation failed: hash is not 32 bytes".to_string())
            }
            None => Err("Key derivation failed: hash is None".to_string()),
        }
    }

    // This returns a base64 encoded string, with the nonce + salt + ciphertext.
    // this should be base64 decoded first, then broken apart into it's parts + decrypted
    pub fn encrypt(password: &str, text: &str) -> Result<String, String> {
        let salt = SaltString::generate(&mut OsRng);
        let key = derive_key(password, &salt)?;

        let cipher = Aes256Gcm::new(&key);
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        cipher
            .encrypt(&nonce, text.as_bytes())
            .map(|ciphertext| {
                BASE64_STANDARD.encode(
                    [
                        nonce.as_slice(),
                        &salt.as_ref().to_string().into_bytes(),
                        &ciphertext,
                    ]
                    .concat(),
                )
            })
            .map_err(|e| e.to_string())
    }

    pub fn decrypt(password: &str, encrypted_b64: &str) -> Result<String, String> {
        let encrypted_bytes = BASE64_STANDARD
            .decode(encrypted_b64.as_bytes())
            .map_err(|e| format!("Error decoding bytes: {}", e.to_string()))?;

        if encrypted_bytes.len() < 44 {
            // 12 bytes nonce + 32 bytes salt
            return Err("Encrypted data is too short".into());
        }

        let (nonce, rest) = encrypted_bytes.split_at(12);
        let (salt, ciphertext) = rest.split_at(22);

        let salt_str = std::str::from_utf8(salt).map_err(|e| format!("Invalid salt: {}", e))?;
        let salt =
            SaltString::from_b64(salt_str).map_err(|e| format!("Failed to create salt: {}", e))?;
        let key = derive_key(password, &salt)?;

        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(&nonce, ciphertext)
            .map(|url_bytes| -> Result<String, String> {
                let unowned_url_str = std::str::from_utf8(&url_bytes).map_err(|e| {
                    format!("failed to decode url bytes to string: {}", e.to_string())
                })?;
                Ok(unowned_url_str.to_string())
            })
            .map_err(|e| e.to_string())?
    }
}

// RUN TEST:
//
#[cfg(test)]
mod tests {
    use std::println;

    use super::*;

    #[test]
    fn test_encrypt_decrypt_success() {
        let password = "super_secret_password";
        let plaintext = "Testing encryption";

        // Test encryption
        let encrypted_data = simple_encryption::encrypt(password, plaintext);
        assert!(encrypted_data.is_ok(), "Encryption should succeed");

        // Test decryption
        let ciphertext = encrypted_data.unwrap();
        println!("{:?}", ciphertext);
        let decrypted_data = simple_encryption::decrypt(password, &ciphertext);

        assert!(
            decrypted_data.is_ok(),
            "{}",
            decrypted_data
                .err()
                .unwrap_or_else(|| "Unknown error".to_string())
        );

        // Check if decrypted data matches original plaintext
        assert_eq!(
            decrypted_data.unwrap(),
            plaintext,
            "Decrypted data should match original plaintext"
        );
    }

    #[test]
    fn test_decrypt_with_wrong_password() {
        let password = "super_secret_password";
        let wrong_password = "wrong_password";
        let plaintext = "Hello, AES-GCM encryption!";

        let encrypted_data = simple_encryption::encrypt(password, plaintext).unwrap();
        let decrypted_data = simple_encryption::decrypt(wrong_password, &encrypted_data);

        assert!(
            decrypted_data.is_err(),
            "Decryption with wrong password should fail"
        );
    }

    // Additional tests can be added here
}
