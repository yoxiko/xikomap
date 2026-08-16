use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::{CaptureScreenshotFormat, CaptureScreenshotParams};
use futures::StreamExt;
use std::time::Duration;
use tracing::debug;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScreenshotResult {
    pub url: String,
    pub file_path: String,
    pub status_code: Option<u16>,
    pub title: String,
    pub final_url: String,
}

pub struct ScreenshotCapture;

impl ScreenshotCapture {
    pub async fn launch() -> Option<Browser> {
        let browser_config = BrowserConfig::builder()
            .new_headless_mode()
            .no_sandbox()
            .disable_default_args()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--ignore-certificate-errors")
            .arg("--window-size=1920,1080")
            .arg("--hide-scrollbars")
            .build()
            .ok()?;

        let (browser, mut handler) = match Browser::launch(browser_config).await {
            Ok(result) => result,
            Err(e) => {
                debug!("Browser launch failed: {}", e);
                return None;
            }
        };

        tokio::spawn(async move {
            while handler.next().await.is_some() {}
        });

        Some(browser)
    }

    pub async fn capture_with_browser(
        browser: &mut Browser,
        url: &str,
        output_dir: &str,
        target_name: &str,
        port: u16,
    ) -> Option<ScreenshotResult> {
        let page = match browser.new_page("about:blank").await {
            Ok(p) => p,
            Err(e) => {
                debug!("Failed to open page: {}", e);
                return None;
            }
        };

        let navigate = tokio::time::timeout(Duration::from_secs(15), page.goto(url)).await;

        match navigate {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                debug!("Navigation failed for {}: {}", url, e);
                return None;
            }
            Err(_) => {
                debug!("Navigation timeout for {}", url);
                return None;
            }
        }

        let final_url = page
            .url()
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| url.to_string());

        let _ = tokio::time::timeout(Duration::from_secs(3), page.wait_for_navigation()).await;

        let title = page
            .evaluate("document.title")
            .await
            .ok()
            .and_then(|r| r.into_value::<String>().ok())
            .unwrap_or_default();

        if std::fs::create_dir_all(output_dir).is_err() {
            return None;
        }

        let file_name = format!("{}_{}_screenshot.png", target_name, port);
        let file_path = format!("{}/{}", output_dir, file_name);

        let params = CaptureScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Png)
            .build();

        let shot = tokio::time::timeout(Duration::from_secs(10), page.screenshot(params)).await;

        match shot {
            Ok(Ok(bytes)) => {
                if std::fs::write(&file_path, bytes).is_err() {
                    return None;
                }
                Some(ScreenshotResult {
                    url: url.to_string(),
                    file_path,
                    status_code: None,
                    title,
                    final_url,
                })
            }
            Ok(Err(e)) => {
                debug!("Screenshot failed for {}: {}", url, e);
                None
            }
            Err(_) => {
                debug!("Screenshot timeout for {}", url);
                None
            }
        }
    }
}