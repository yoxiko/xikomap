pub struct ScreenshotResult {
    pub url: String,
    pub file_path: String,
    pub title: String,
    pub status_code: Option<u16>,
    pub final_url: String,
}

pub struct ScreenshotCapture;

impl ScreenshotCapture {
    pub async fn launch() -> Option<MockBrowser> {
        None
    }

    pub async fn capture_with_browser(
        _browser: &mut MockBrowser,
        _url: &str,
        _dir: &str,
        _safe_name: &str,
        _port: u16,
    ) -> Option<ScreenshotResult> {
        None
    }
}

pub struct MockBrowser;

impl MockBrowser {
    pub async fn close(self) {}
}