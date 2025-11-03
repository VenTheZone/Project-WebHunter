use headless_chrome::{Browser, LaunchOptions};
use std::fs;
use std::io::Write;
use url::Url;

pub fn get_snapshot_filename_base(url: &Url, method: &str, payload: &str) -> String {
    let path = url.path().replace("/", "_");
    let sanitized_path = path.trim_start_matches('_').trim_start_matches('.');
    format!(
        "{}_{}_{}",
        sanitized_path,
        method,
        payload.replace("/", "_").replace(":", "_")
    )
}

pub async fn take_snapshot(url: Url, domain: String, method: String, payload: String, body: String) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || {
        let snapshot_dir = format!("{}/snapshots", domain);
        fs::create_dir_all(&snapshot_dir)?;

        let filename_base = get_snapshot_filename_base(&url, &method, &payload);

        // HTML snapshot
        let html_filename = format!("{}/{}.html", snapshot_dir, filename_base);
        let mut file = fs::File::create(&html_filename)?;
        file.write_all(body.as_bytes())?;
        println!("HTML snapshot saved: {}", html_filename);

        // PNG snapshot
        let png_filename = format!("{}/{}.png", snapshot_dir, filename_base);
        let browser = Browser::new(LaunchOptions {
            headless: true,
            ..Default::default()
        })
        .map_err(std::io::Error::other)?;

        let tab = browser
            .new_tab()
            .map_err(std::io::Error::other)?;

        let base_href = format!("{}://{}/", url.scheme(), url.host_str().unwrap_or(""));
        let modified_body = format!(
            "<base href=\"{}\">\n{}",
            base_href, body
        );
        let data_url = format!("data:text/html,{}", modified_body);
        tab.navigate_to(&data_url)
            .map_err(std::io::Error::other)?;

        let png_data = tab
            .capture_screenshot(
                headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
                None,
                None,
                true,
            )
            .map_err(std::io::Error::other)?;

        fs::write(&png_filename, png_data)?;
        println!("PNG snapshot saved: {}", png_filename);

        Ok(())
    })
    .await
    .map_err(std::io::Error::other)?
}
