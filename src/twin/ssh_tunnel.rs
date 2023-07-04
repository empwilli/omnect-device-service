use super::Twin;
use crate::{twin, ReportProperty};
use anyhow::{Context, Result};
use futures::executor;
use log::{error, info, warn};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str;
use std::sync::Mutex;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use uuid::Uuid;

use std::ops::Drop;

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum TunnelState {
    Init,
    Active,
    Closed,
    Failed(String),
}

#[derive(Clone, Serialize)]
struct Tunnel {
    tunnel_id: String,
    state: TunnelState,
}

static MAX_ACTIVE_TUNNELS: usize = 10;

static TUNNEL_TIMEOUT_SECS: usize = 30;

static SSH_KEY_DIR: &str = "/home/ssh_user/.ssh";
static SSH_KEY_NAME: &str = "bastion";
static SSH_KEY_TYPE: &str = "ed25519";

lazy_static::lazy_static! {
    static ref CONTROL_SOCKET_DIR: String = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| {
        warn!("XDG_RUNTIME_DIR not set, defaulting to /tmp/omnect-device-service/sockets");
        "/tmp/omnect-device-service/sockets".to_string()
    });

    static ref BASTION_SSH_USER: String = std::env::var("SSH_TUNNEL_USER").unwrap_or_else(|_| "ssh_user".to_string());
    static ref BASTION_SSH_PORT: u16 = std::env::var("SSH_TUNNEL_PORT").map_or_else(|_| Ok(22),
                                                                            |port| port.parse::<u16>()).unwrap();
    static ref BASTION_HOST: String = std::env::var("BASTION_HOST").unwrap_or_else(|_| "bastion".to_string());
    static ref BASTION_SOCKET_DIR: String = std::env::var("BASTION_SOCKET_DIR").unwrap_or_else(|_| "/home/ssh_user/.ssh".to_string());

    static ref ACTIVE_TUNNELS: Mutex<HashMap<String, Tunnel>> = Mutex::new(HashMap::new());
    static ref CLOSED_TUNNELS: Mutex<VecDeque<Tunnel>> = Mutex::new(VecDeque::new());
}

fn get_pub_key_path() -> PathBuf {
    Path::new(SSH_KEY_DIR).join(format!("{}.pub", SSH_KEY_NAME))
}

fn get_priv_key_path() -> PathBuf {
    Path::new(SSH_KEY_DIR).join(SSH_KEY_NAME)
}

fn get_cert_path(name: &str) -> PathBuf {
    Path::new(SSH_KEY_DIR).join(format!("{}-{}-cert.pub", SSH_KEY_NAME, name))
}

fn get_control_socket(name: &str) -> PathBuf {
    Path::new(&*CONTROL_SOCKET_DIR).join(name)
}

fn create_control_socket_path() -> Result<()> {
    Ok(fs::create_dir_all(&*CONTROL_SOCKET_DIR)?)
}

fn create_or_get_pub_key() -> Result<Vec<u8>> {
    // lock against concurrent access to the key pair.
    static KEY_FILE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
    let _guard = KEY_FILE_LOCK.lock().unwrap();

    let pub_key_path = get_pub_key_path();

    // check if there is already a key pair, if not, create it first
    if !pub_key_path.exists() {
        fs::create_dir_all(SSH_KEY_DIR).unwrap();
        let result = std::process::Command::new("ssh-keygen")
            .stdout(Stdio::piped())
            .args(["-q"])
            .args(["-f", get_priv_key_path().to_str().unwrap()])
            .args(["-t", SSH_KEY_TYPE])
            .args(["-N", ""])
            .output();

        match &result {
            Err(error) => {
                error!("Failed to create ssh key pair: {}", error);
                anyhow::bail!("Error on ssh key creation.");
            }
            Ok(output) => {
                if !output.status.success() {
                    error!(
                        "Failed to create ssh key pair: {}",
                        str::from_utf8(&output.stderr).unwrap()
                    );
                    anyhow::bail!("Error on ssh key creation.");
                }
            }
        }
    }

    match fs::read(pub_key_path.to_str().unwrap()) {
        Ok(pub_key) => Ok(pub_key),
        Err(err) => {
            error!("Failed to open ssh public key: {}", err);
            anyhow::bail!("Error reading ssh public key.");
        }
    }
}

pub fn refresh_ssh_tunnel_status(_in_json: serde_json::Value) -> Result<Option<serde_json::Value>> {
    info!("ssh tunnel status requested");

    twin::get_or_init(None).report(&ReportProperty::SshTunnelStatus)?;

    Ok(None)
}

/// Get the public ssh key of the device
///
/// # Returns
/// This function returns a json document containing the public key in PEM
/// format. The document is formatted as follows:
/// ```json
/// {
///   "pub_key": "..."
/// }
/// ```
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

// RAII handle to the temporary bastion host certificate
struct CertificateFile {
    path: PathBuf,
}

impl CertificateFile {
    fn new(path: impl AsRef<Path>, data: &[u8]) -> Result<CertificateFile> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(path.as_ref())?;
        f.write_all(data)?;
        Ok(CertificateFile {
            path: path.as_ref().to_path_buf(),
        })
    }
}

impl Drop for CertificateFile {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            warn!(
                "Failed to delete certificate \"{}\": {}",
                self.path.to_str().unwrap(),
                err
            );
        }
    }
}

fn activate_tunnel_state(tunnel_id: &str) {
    if let Some(tunnel) = ACTIVE_TUNNELS
        .lock()
        .unwrap() // safe
        .get_mut(tunnel_id)
    {
        tunnel.state = TunnelState::Active;
    } else {
        warn!("Failed to update tunnel state.");
    }
}

fn terminate_tunnel_state(tunnel_id: &str, state: TunnelState) {
    let mut tunnel = match ACTIVE_TUNNELS
        .lock()
        .unwrap() // safe
        .remove(tunnel_id)
    {
        Some(tunnel) => tunnel,
        None => {
            warn!("Failed to update tunnel state.");
            return;
        }
    };

    tunnel.state = state;
    let mut queue = CLOSED_TUNNELS.lock().unwrap();
    queue.push_back(tunnel);
}

fn create_tunnel_handle(tunnel_id: String) -> Result<()> {
    let mut active_tunnels = ACTIVE_TUNNELS.lock().unwrap();
    if active_tunnels.len() >= MAX_ACTIVE_TUNNELS {
        anyhow::bail!("ssh tunnel limit reached.")
    }

    active_tunnels.insert(
        tunnel_id.clone(),
        Tunnel {
            tunnel_id,
            state: TunnelState::Init,
        },
    );

    Ok(())
}

#[derive(Deserialize)]
struct OpenSshTunnelArgs {
    tunnel_id: String,
    certificate: Vec<u8>,
}

/// Instruct the device to establish an ssh tunnel to the bastion host
///
/// # Arguments
/// * `args` - json object describing the properties of the ssh tunnel. This
/// object must have the following structure:
/// ```json
/// {
///   "tunnel_id": "...", // uuid identifying the tunnel
///   "certificate": "..." // PEM formatted ssh certificate which the device uses to create the tunnel
/// }
/// ```
///
/// # Note
/// This method is synchronous. It returns when the tunnel is created successfully.
pub fn open_ssh_tunnel(args: serde_json::Value) -> Result<Option<serde_json::Value>> {
    info!("open ssh tunnel requested");

    let args: OpenSshTunnelArgs =
        serde_json::from_value(args).map_err(|e| anyhow::anyhow!("{e}"))?;

    let tunnel_id = Uuid::parse_str(&args.tunnel_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .as_simple()
        .to_string();

    if ACTIVE_TUNNELS.lock().unwrap().contains_key(&tunnel_id) {
        anyhow::bail!("Can't handle multiple connections with the same UUID");
    }

    // create handle for this tunnel to reference later on, e.g. for reporting
    create_tunnel_handle(tunnel_id.clone())?;

    // store the certificate so that ssh can use it for login on the bastion host
    let cert_path = get_cert_path(&tunnel_id);
    let cert_file =
        CertificateFile::new(cert_path, &args.certificate).map_err(|e| anyhow::anyhow!("{e}"))?;

    // create dir for control sockets if it does not exist yet
    create_control_socket_path()?;

    // now spawn the ssh tunnel: we tell ssh to allocate a reverse tunnel on the
    // bastion host bound to a socket file there. Furthermore, we tell ssh to 1)
    // echo once the connection was successful, so that we can check from here
    // when we can signal a successful connection, 2) we tell it to sleep. The
    // latter is so that the connection is closed after it remains unused for
    // some time.
    let mut ssh_command = Command::new("ssh");
    ssh_command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["-M"])
        .args(["-S", get_control_socket(&tunnel_id).to_str().unwrap()])
        .args(["-i", get_priv_key_path().to_str().unwrap()])
        .args([
            "-o",
            &format!(
                "CertificateFile={}",
                get_cert_path(&tunnel_id).to_str().unwrap()
            ),
        ])
        .args([
            "-R",
            &format!(
                "{}/{}:localhost:{}",
                *BASTION_SOCKET_DIR, tunnel_id, *BASTION_SSH_PORT
            ),
        ])
        .args([&format!("{}@{}", *BASTION_SSH_USER, *BASTION_HOST)])
        .args(["-o", "ExitOnForwardFailure=yes"]) // ensure ssh terminates if anything goes south
        .args(["-o", "StrictHostKeyChecking=no"]) // allow bastion host to be redeployed
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .args([&format!(
            "echo established && sleep {}",
            TUNNEL_TIMEOUT_SECS
        )]);

    let mut ssh_process = ssh_command.spawn().map_err(|e| anyhow::anyhow!("{e}"))?;

    let stdout = ssh_process.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();

    let child_tunnel_id = tunnel_id.clone();
    tokio::spawn(async move {
        // capture the certificate file handle, drop will cleanup the
        // certificate file.
        let _cert_file = cert_file;

        info!("Waiting for connection to close: {}", child_tunnel_id);

        let output = match ssh_process.wait_with_output().await {
            Ok(output) => output,
            Err(err) => {
                terminate_tunnel_state(&child_tunnel_id, TunnelState::Failed(err.to_string()));
                let _ = twin::get_or_init(None).report(&ReportProperty::SshTunnelStatus);
                error!("Could not retrieve output from ssh process: {}", err);
                return;
            }
        };

        if !output.status.success() {
            error!(
                "Failed to establish ssh tunnel: {}",
                str::from_utf8(&output.stderr).unwrap()
            );
            terminate_tunnel_state(
                &child_tunnel_id,
                TunnelState::Failed(str::from_utf8(&output.stderr).unwrap().to_string()),
            );
            let _ = twin::get_or_init(None).report(&ReportProperty::SshTunnelStatus);
            return;
        }

        info!("Closed ssh tunnel: {}", child_tunnel_id);
        terminate_tunnel_state(&child_tunnel_id, TunnelState::Closed);
        let _ = twin::get_or_init(None).report(&ReportProperty::SshTunnelStatus);
    });

    let response = executor::block_on(reader.next_line());
    match response {
        Ok(Some(msg)) => {
            if msg == "established" {
                // now mark the tunnel as active
                activate_tunnel_state(&tunnel_id);

                twin::get_or_init(None).report(&ReportProperty::SshTunnelStatus)?;

                Ok(None)
            } else {
                error!("Got unexpected response from ssh server: {}", msg);
                anyhow::bail!("Failed to establish ssh tunnel");
            }
        }
        Ok(None) => {
            // async task takes care of handling stderr
            anyhow::bail!("Failed to establish ssh tunnel");
        }
        Err(err) => {
            error!("Could not read from ssh process: {}", err);
            anyhow::bail!("Failed to establish ssh tunnel");
        }
    }
}

#[derive(Deserialize)]
struct CloseSshTunnelArgs {
    tunnel_id: String,
}

/// Instruct the device to tear down an ssh tunnel to the bastion host
///
/// # Arguments
/// * `args` - json object describing the ssh tunnel. This object must have the following structure:
/// ```json
/// {
///   "tunnel_id": "...", // uuid identifying the tunnel
/// }
/// ```
pub fn close_ssh_tunnel(args: serde_json::Value) -> Result<Option<serde_json::Value>> {
    info!("close ssh tunnel requested");

    twin::get_or_init(None).report(&ReportProperty::SshTunnelStatus)?;

    let args: CloseSshTunnelArgs = match serde_json::from_value(args) {
        Ok(args) => args,
        Err(err) => {
            error!("Retrieved malformed argument pack: {err}");
            anyhow::bail!("Malformed argument pack")
        }
    };

    let tunnel_id = Uuid::parse_str(&args.tunnel_id)?.as_simple().to_string();

    let result = std::process::Command::new("ssh")
        .stdout(Stdio::piped())
        .args(["-O", "exit"])
        .args(["-S", get_control_socket(&tunnel_id).to_str().unwrap()])
        .args([&*BASTION_HOST])
        .output()?;

    if !result.status.success() {
        warn!(
            "Unexpected error upon closing tunnel \"{}\": {}",
            tunnel_id,
            str::from_utf8(&result.stderr).unwrap()
        );
    }

    Ok(None)
}

impl Twin {
    pub fn report_ssh_tunnel_status(&mut self) -> Result<()> {
        #[derive(Serialize)]
        struct SshTunnelReport {
            status: Vec<Tunnel>,
        }

        let mut tunnel_info = ACTIVE_TUNNELS
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();

        let mut closed_tunnels = CLOSED_TUNNELS
            .lock()
            .unwrap()
            .drain(0..)
            .collect::<Vec<_>>();

        tunnel_info.append(&mut closed_tunnels);

        let ssh_tunnel_report = SshTunnelReport {
            status: tunnel_info,
        };

        self.report_impl(json!({ "ssh_tunnel_status": json!(ssh_tunnel_report) }))
            .context("report_ssh_status")
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn certificate_file_raii() {
        let cert_dir = tempdir().unwrap();
        let cert_file = cert_dir.path().join("testfile");
        {
            let _file = CertificateFile::new(&cert_file, &[0xc0, 0xff, 0xee]).unwrap();
            assert!(cert_file.exists());
        }
        assert!(!cert_file.exists());
    }
}
