use super::Twin;
use crate::{twin, ReportProperty};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::json;

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
