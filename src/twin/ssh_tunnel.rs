use super::Twin;
use crate::{twin, ReportProperty};
use anyhow::{Context, Result};
use log::{info, warn};
use once_cell::sync::Lazy;
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;
use std::sync::Mutex;

static SSH_KEY_DIR: &str = "/home/ssh_user/.ssh";
static SSH_KEY_NAME: &str = "bastion";
static SSH_KEY_TYPE: &str = "ed25519";

fn get_pub_key_path() -> PathBuf {
    Path::new(SSH_KEY_DIR).join(format!("{}.pub", SSH_KEY_NAME))
}

fn get_priv_key_path() -> PathBuf {
    Path::new(SSH_KEY_DIR).join(SSH_KEY_NAME)
}

fn create_or_get_pub_key() -> Result<Vec<u8>> {
    // lock against concurrent access to the key pair.
    static KEY_FILE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
    let _guard = KEY_FILE_LOCK.lock().unwrap();

    let pub_key_path = get_pub_key_path();

    // check if there is already a key pair, if not, create it first
    if !pub_key_path.exists() {
        fs::create_dir_all(SSH_KEY_DIR).unwrap();
        let result = Command::new("ssh-keygen")
            .args(["-q"])
            .args(["-f", &format!("{}", get_priv_key_path().to_str().unwrap())])
            .args(["-t", SSH_KEY_TYPE])
            .args(["-N", ""])
            .output();

        match &result {
            Err(error) => {
                log::error!("Failed to create ssh key pair: {}", error);
                anyhow::bail!("Error on ssh key creation.");
            }
            Ok(output) => {
                if !output.status.success() {
                    log::error!(
                        "Failed to create ssh key pair: {}",
                        str::from_utf8(&output.stderr).unwrap()
                    );
                    anyhow::bail!("Error on ssh key creation.");
                }
            }
        }
    }

    match fs::read(&format!("{}", pub_key_path.to_str().unwrap())) {
        Ok(pub_key) => Ok(pub_key),
        Err(err) => {
            log::error!("Failed to open ssh public key: {}",
                        err);
            anyhow::bail!("Error reading ssh public key.");
        },
    }
}
}

pub fn get_ssh_pub_key(_in_json: serde_json::Value) -> Result<Option<serde_json::Value>> {
    info!("ssh public key requested");

    twin::get_or_init(None).report(&ReportProperty::SshTunnelStatus)?;

    #[derive(Serialize)]
    struct PublicKeyResponse {
        pub_key: Vec<u8>,
    }

    let response = PublicKeyResponse {
        pub_key: create_or_get_pub_key()?,
    };

    Ok(Some(json!(response)))
}

impl Twin {
    pub fn report_ssh_tunnel_status(&mut self) -> Result<()> {
        #[derive(Debug, Serialize)]
        struct SshTunnelReport {
            #[serde(default)]
            test_feature: String,
        }

        let ssh_tunnel_report = SshTunnelReport {
            test_feature: "Foobar!".to_string(),
        };

        self.report_impl(json!({ "ssh_tunnel_status": json!(ssh_tunnel_report) }))
            .context("report_ssh_status")
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}
