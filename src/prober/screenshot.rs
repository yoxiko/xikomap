use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::{CaptureScreenshotFormat, CaptureScreenshotParams};
use futures::StreamExt;
use std::time::Duration;

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
    pub async fn capture(
        url: &str,
        output_dir: &str,
        target_name: &str,
        port: u16,
    ) -> Option<ScreenshotResult> {
        let browser_config = BrowserConfig::builder()
            .with_head()
            .no_sandbox()
            .disable_default_args()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--ignore-certificate-errors")
            .arg("--window-size=1920,1080")
            .build()
            .ok()?;

        // ИСПРАВЛЕНО: добавлен mut перед browser
        let (mut browser, mut handler) = match Browser::launch(browser_config).await {
            Ok(result) => result,
            Err(_) => return None,
        };

        let _handler_task = tokio::spawn(async move {
            while handler.next().await.is_some() {}
        });

        let page = match browser.new_page("about:blank").await {
            Ok(p) => p,
            Err(_) => return None,
        };

        let navigate_result = tokio::time::timeout(Duration::from_secs(15), page.goto(url)).await;

        let _response = match navigate_result {
            Ok(Ok(resp)) => Some(resp),
            _ => {
                let _ = browser.close().await;
                return None;
            }
        };

        let status_code = None;

        let final_url = page
            .url()
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| url.to_string());

        let _ =
            tokio::time::timeout(Duration::from_secs(3), page.wait_for_navigation()).await;

        let title = page
            .evaluate("document.title")
            .await
            .ok()
            .and_then(|r| r.into_value::<String>().ok())
            .unwrap_or_default();

        let file_name = format!("{}_{}_screenshot.png", target_name, port);
        let file_path = format!("{}/{}", output_dir, file_name);

        if std::fs::create_dir_all(output_dir).is_err() {
            let _ = browser.close().await;
            return None;
        }

        let params = CaptureScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Png)
            .build();

        let screenshot_result =
            tokio::time::timeout(Duration::from_secs(10), page.screenshot(params)).await;

        match screenshot_result {
            Ok(Ok(bytes)) => {
                if std::fs::write(&file_path, bytes).is_err() {
                    let _ = browser.close().await;
                    return None;
                }
                let _ = browser.close().await;
                Some(ScreenshotResult {
                    url: url.to_string(),
                    file_path,
                    status_code,
                    title,
                    final_url,
                })
            }
            _ => {
                let _ = browser.close().await;
                None
            }
        }
    }

    pub async fn capture_multiple(
        urls: &[(String, u16)],
        output_dir: &str,
        target_name: &str,
    ) -> Vec<ScreenshotResult> {
        let mut results = Vec::new();

        for (url, port) in urls {
            if let Some(result) = Self::capture(url, output_dir, target_name, *port).await {
                results.push(result);
            }
        }

        results
    }
}