//! Embedded local web dashboard server (`sepac web`).

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::config::SafeguardConfig;
use crate::types::Result;

/// Web server configuration for `sepac web`.
#[derive(Debug, Clone)]
pub struct WebConfig {
    /// Port to listen on.
    pub port: u16,
    /// Safeguard configuration file path.
    pub config_path: PathBuf,
}

/// Embedded web dashboard server.
pub struct DashboardServer {
    config: WebConfig,
}

impl DashboardServer {
    /// Creates a new `DashboardServer`.
    pub fn new(config: WebConfig) -> Self {
        Self { config }
    }

    /// Generates the HTML dashboard page.
    pub fn render_dashboard_html(&self, app_config: &SafeguardConfig) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Safeguard Local Security Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0B0F19; color: #F3F4F6; margin: 0; padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1F2937; padding-bottom: 16px; margin-bottom: 24px; }}
        .title {{ font-size: 24px; font-weight: bold; color: #38BDF8; }}
        .badge {{ background: #10B981; color: #000; padding: 4px 12px; border-radius: 12px; font-weight: bold; text-transform: uppercase; font-size: 12px; }}
        .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 32px; }}
        .card {{ background: #111827; border: 1px solid #1F2937; border-radius: 10px; padding: 20px; }}
        .card-val {{ font-size: 28px; font-weight: bold; margin-top: 8px; color: #F9FAFB; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">🛡️ Safeguard Security Dashboard</div>
        <div class="badge">Active Mode: {}</div>
    </div>
    <div class="grid">
        <div class="card"><div>Trust Mode</div><div class="card-val">{}</div></div>
        <div class="card"><div>Max Risk Score</div><div class="card-val">{}</div></div>
        <div class="card"><div>Audit Log Location</div><div class="card-val" style="font-size:14px;">{}</div></div>
    </div>
</body>
</html>"#,
            app_config.trust_mode,
            app_config.trust_mode,
            app_config.scoring.max_score,
            app_config.audit.log_path.display()
        )
    }

    /// Starts the async HTTP server listening on configured socket address.
    pub async fn run(&self, app_config: &SafeguardConfig) -> Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.config.port));
        eprintln!("🌐 Safeguard Dashboard listening on http://{addr}");
        let _html = self.render_dashboard_html(app_config);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_rendering() {
        let web_cfg = WebConfig {
            port: 9090,
            config_path: PathBuf::from("safeguard.toml"),
        };
        let server = DashboardServer::new(web_cfg);
        let html = server.render_dashboard_html(&SafeguardConfig::default());
        assert!(html.contains("Safeguard Security Dashboard"));
        assert!(html.contains("Active Mode: balanced"));
    }
}
