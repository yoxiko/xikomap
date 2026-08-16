use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::{CaptureScreenshotFormat, CaptureScreenshotParams};
use futures::StreamExt;
use std::time::Duration;
use tracing::{debug, warn};

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
        let browser_config = match BrowserConfig::builder()
            .new_headless_mode()
            .no_sandbox()
            .disable_default_args()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--ignore-certificate-errors")
            .arg("--window-size=1920,1080")
            .arg("--hide-scrollbars")
            .arg("--disable-web-security")
            .arg("--disable-features=IsolateOrigins,site-per-process")
            .build()
        {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("Browser config failed: {}", e);
                return None;
            }
        };

        match Browser::launch(browser_config).await {
            Ok((browser, mut handler)) => {
                tokio::spawn(async move {
                    while let Some(event) = handler.next().await {
                        debug!("Browser event: {:?}", event);
                    }
                });
                Some(browser)
            }
            Err(e) => {
                warn!("Browser launch failed: {}. Chrome/Chromium may not be installed.", e);
                None
            }
        }
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
                debug!("Failed to create page: {}", e);
                return None;
            }
        };

        let navigate = tokio::time::timeout(Duration::from_secs(20), page.goto(url)).await;

        match navigate {
            Ok(Ok(_nav_response)) => {
                // Упрощаем - не пытаемся получить status_code из сложной структуры
                let status_code = None;

                let final_url = page
                    .url()
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| url.to_string());

                let _ = tokio::time::timeout(Duration::from_secs(5), page.wait_for_navigation()).await;

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

                match tokio::time::timeout(Duration::from_secs(15), page.screenshot(params)).await {
                    Ok(Ok(bytes)) => {
                        if std::fs::write(&file_path, bytes).is_err() {
                            return None;
                        }
                        Some(ScreenshotResult {
                            url: url.to_string(),
                            file_path,
                            status_code,
                            title,
                            final_url,
                        })
                    }
                    Ok(Err(e)) => {
                        debug!("Screenshot capture failed for {}: {}", url, e);
                        None
                    }
                    Err(_) => {
                        debug!("Screenshot timeout for {}", url);
                        None
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("Navigation failed for {}: {}", url, e);
                None
            }
            Err(_) => {
                debug!("Navigation timeout for {}", url);
                None
            }
        }
    }
}