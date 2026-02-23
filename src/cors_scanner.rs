use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use indicatif::ProgressBar;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Deserialize, Clone)]
pub struct CorsVulnerability {
    pub url: Url,
    pub origin: String,
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
}

pub struct CorsScanner<'a> {
    target_url: Url,
    discovered_urls: Vec<Url>,
    test_origins: Vec<String>,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
    client: Client,
    found: HashSet<String>,
}

impl<'a> CorsScanner<'a> {
    pub fn new(
        target_url: Url,
        discovered_urls: Vec<Url>,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        let test_origins = vec![
            "https://evil.com".to_string(),
            "null".to_string(),
            "https://target.com.evil.com".to_string(),
            "https://subdomain.target.com.evil.com".to_string(),
            "http://192.168.1.1".to_string(),
        ];

        Self {
            target_url,
            discovered_urls,
            test_origins,
            reporter,
            rate_limiter,
            client: Client::new(),
            found: HashSet::new(),
        }
    }

    pub fn targets_count(&self) -> usize {
        self.discovered_urls.len() * self.test_origins.len()
    }

    pub async fn scan(
        &mut self,
        pb: &ProgressBar,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("Starting CORS Misconfiguration scan...");

        let urls: Vec<Url> = self.discovered_urls.clone();
        let origins: Vec<String> = self.test_origins.clone();

        for base_url in urls {
            for origin in &origins {
                pb.set_message(format!("Testing CORS: {}", base_url));

                self.test_cors_endpoint(&base_url, origin, pb).await?;

                pb.inc(1);
            }
        }

        pb.finish_with_message("CORS scan complete.");
        Ok(())
    }

    async fn test_cors_endpoint(
        &mut self,
        url: &Url,
        test_origin: &str,
        _pb: &ProgressBar,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.rate_limiter.wait().await;

        let url_str = url.to_string();
        let host = url.host().map(|h| h.to_string()).unwrap_or_default();
        let referer = format!("{}://{}/", url.scheme(), host);

        let response = self
            .client
            .get(&url_str)
            .header("Origin", test_origin)
            .header("Referer", referer)
            .send()
            .await?;

        let _status = response.status();
        let headers = response.headers();

        let allow_origin = headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let allow_credentials = headers
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let allow_methods = headers
            .get("access-control-allow-methods")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let allow_headers = headers
            .get("access-control-allow-headers")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let Some(acao) = &allow_origin {
            let finding_key = format!("{}:{}:{}", url, test_origin, acao);
            if self.found.contains(&finding_key) {
                return Ok(());
            }

            let target_host = self.target_url.host_str().unwrap_or("");
            let severity =
                self.classify_vulnerability(acao, allow_credentials.as_deref(), target_host);
            if severity != "None" {
                let vuln = CorsVulnerability {
                    url: self.target_url.clone(),
                    origin: test_origin.to_string(),
                    vuln_type: severity.clone(),
                    severity: severity.clone(),
                    description: format!(
                        "Origin '{}' -> ACAO: '{}', ACAC: '{}', ACAM: '{}', ACAH: '{}'",
                        test_origin,
                        acao,
                        allow_credentials.as_deref().unwrap_or("not set"),
                        allow_methods.as_deref().unwrap_or("not set"),
                        allow_headers.as_deref().unwrap_or("not set")
                    ),
                };
                self.reporter.report_cors(&vuln);
                self.found.insert(finding_key);
            }
        }

        Ok(())
    }

    fn classify_vulnerability(
        &self,
        allow_origin: &str,
        allow_credentials: Option<&str>,
        target_host: &str,
    ) -> String {
        if allow_origin == "*" && allow_credentials == Some("true") {
            "Critical: Wildcard with Credentials".to_string()
        } else if allow_origin == "null" {
            "High: Null Origin Allowed".to_string()
        } else if allow_credentials == Some("true") && !allow_origin.starts_with(target_host) {
            "High: Credentials with Untrusted Origin".to_string()
        } else if allow_origin.contains("evil.com") || allow_origin.contains("attacker") {
            "High: Arbitrary Origin Reflected".to_string()
        } else if allow_origin != "*" && !allow_origin.is_empty() {
            "Medium: Permissive Origin".to_string()
        } else {
            "None".to_string()
        }
    }
}
