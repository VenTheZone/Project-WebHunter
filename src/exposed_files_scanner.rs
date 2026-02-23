use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use indicatif::ProgressBar;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead};
use std::sync::Arc;
use url::Url;

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct ExposedFileVulnerability {
    pub url: Url,
    pub exposed_path: String,
    pub vuln_type: String,
    pub description: String,
}

pub struct ExposedFilesScanner<'a> {
    target_url: Url,
    discovered_urls: Vec<Url>,
    source_map_paths: Vec<String>,
    debug_paths: Vec<String>,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
    client: Client,
    found: HashSet<String>,
}

impl<'a> ExposedFilesScanner<'a> {
    pub fn new(
        target_url: Url,
        discovered_urls: Vec<Url>,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        let source_map_paths = Self::load_list("wordlists/exposed_files/source_maps.txt");
        let debug_paths = Self::load_list("wordlists/exposed_files/debug_endpoints.txt");

        Self {
            target_url,
            discovered_urls,
            source_map_paths,
            debug_paths,
            reporter,
            rate_limiter,
            client: Client::new(),
            found: HashSet::new(),
        }
    }

    fn load_list(path: &str) -> Vec<String> {
        let mut list = Vec::new();
        if let Ok(file) = fs::File::open(path) {
            let reader = io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                if !line.trim().is_empty() {
                    list.push(line.trim().to_string());
                }
            }
        }
        if list.is_empty() {
            list.extend([
                ".map".to_string(),
                "main.js.map".to_string(),
                "app.js.map".to_string(),
                "bundle.js.map".to_string(),
            ]);
        }
        list
    }

    pub fn targets_count(&self) -> usize {
        let base_paths = self.debug_paths.len() * self.discovered_urls.len();
        let source_maps = self.source_map_paths.len();
        base_paths + source_maps
    }

    pub async fn scan(
        &mut self,
        pb: &ProgressBar,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("Starting Exposed Files scan...");

        self.check_debug_endpoints(pb).await?;
        self.check_source_maps(pb).await?;

        pb.finish_with_message("Exposed Files scan complete.");
        Ok(())
    }

    async fn check_debug_endpoints(
        &mut self,
        pb: &ProgressBar,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.debug_paths.is_empty() {
            self.debug_paths = vec![
                "debug".to_string(),
                "env".to_string(),
                "config".to_string(),
                "api/debug".to_string(),
                "api/config".to_string(),
                "api/env".to_string(),
                ".env".to_string(),
                "config.json".to_string(),
                "settings.json".to_string(),
                "debug.json".to_string(),
            ];
        }

        for base_url in &self.discovered_urls {
            for path in &self.debug_paths {
                pb.set_message(format!("Checking: {}/{}", base_url, path));

                let test_url = base_url.join(path)?;
                let url_str = test_url.to_string();

                if self.found.contains(&url_str) {
                    continue;
                }

                self.rate_limiter.wait().await;

                let response = self.client.get(&url_str).send().await?;

                if response.status().as_u16() == 200 {
                    let content_type = response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                        .unwrap_or_default();

                    let body = response.text().await?;
                    let body_len = body.len();

                    if body_len > 0 && !body.contains("404") && !body.contains("Not Found") {
                        let vuln = ExposedFileVulnerability {
                            url: self.target_url.clone(),
                            exposed_path: format!("{}/{}", base_url, path),
                            vuln_type: "Exposed Debug Endpoint".to_string(),
                            description: format!(
                                "Debug endpoint exposed at {} ({} bytes, Content-Type: {})",
                                url_str, body_len, content_type
                            ),
                        };
                        self.reporter.report_exposed_files(&vuln);
                        self.found.insert(url_str);
                    }
                }

                pb.inc(1);
            }
        }

        Ok(())
    }

    async fn check_source_maps(
        &mut self,
        pb: &ProgressBar,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.source_map_paths.is_empty() {
            self.source_map_paths = vec![
                ".map".to_string(),
                "main.js.map".to_string(),
                "app.js.map".to_string(),
                "bundle.js.map".to_string(),
            ];
        }

        let js_patterns = vec!["main.js", "app.js", "bundle.js", "chunk.js", "vendor.js"];

        for base_url in &self.discovered_urls {
            for js_pattern in &js_patterns {
                for map_path in &self.source_map_paths {
                    pb.set_message(format!(
                        "Checking source map: {}/{}.{}",
                        base_url, js_pattern, map_path
                    ));

                    let test_url = base_url.join(&format!("{}.{}", js_pattern, map_path))?;
                    let url_str = test_url.to_string();

                    if self.found.contains(&url_str) {
                        continue;
                    }

                    self.rate_limiter.wait().await;

                    if let Ok(response) = self.client.get(&url_str).send().await {
                        if response.status().as_u16() == 200 {
                            if let Ok(body) = response.text().await {
                                if body.contains("\"sources\":")
                                    || body.starts_with("{\n  \"version\":")
                                {
                                    let vuln = ExposedFileVulnerability {
                                        url: self.target_url.clone(),
                                        exposed_path: url_str.clone(),
                                        vuln_type: "Source Map Exposure".to_string(),
                                        description: format!("Source map file exposed at {}. This may leak source code.", url_str),
                                    };
                                    self.reporter.report_exposed_files(&vuln);
                                    self.found.insert(url_str);
                                }
                            }
                        }
                    }

                    pb.inc(1);
                }
            }
        }

        Ok(())
    }
}
