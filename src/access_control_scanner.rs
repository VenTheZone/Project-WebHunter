use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use indicatif::ProgressBar;
use reqwest::Client;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Clone)]
pub struct AccessControlVulnerability {
    pub url: Url,
    pub vuln_type: String,
    pub description: String,
    pub severity: String,
    pub payload: String,
}

pub struct AccessControlScanner<'a> {
    target_url: Url,
    discovered_urls: Vec<Url>,
    sensitive_paths: Vec<String>,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
    client: Client,
}

impl<'a> AccessControlScanner<'a> {
    pub fn new(
        target_url: Url,
        discovered_urls: Vec<Url>,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            target_url,
            discovered_urls,
            sensitive_paths: Vec::new(),
            reporter,
            rate_limiter,
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }

    pub fn load_sensitive_paths(&mut self, paths: Vec<String>) {
        self.sensitive_paths = paths;
    }

    pub async fn scan(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        pb.set_message("Scanning for Access Control vulnerabilities...");

        // 1. Forced Browsing
        self.check_forced_browsing(pb).await;

        // 2. IDOR & Method Override on discovered URLs
        for url in &self.discovered_urls {
            self.check_idor(url, pb).await;
            self.check_method_override(url, pb).await;
        }

        Ok(())
    }

    async fn check_forced_browsing(&self, pb: &ProgressBar) {
        pb.set_message("Checking for Forced Browsing vulnerabilities...");

        for path in &self.sensitive_paths {
            let mut target = self.target_url.clone();
            target.set_path(path);

            // Respect rate limiting
            self.rate_limiter.wait().await;

            if let Ok(response) = self.client.get(target.clone()).send().await {
                if response.status().is_success() {
                    let vuln = AccessControlVulnerability {
                        url: target,
                        vuln_type: "Forced Browsing".to_string(),
                        description: format!(
                            "Sensitive path accessible without authentication: {}",
                            path
                        ),
                        severity: "High".to_string(),
                        payload: path.clone(),
                    };
                    self.reporter.report_access_control(&vuln);
                }
            }
            pb.inc(1);
        }
    }

    async fn check_idor(&self, url: &Url, pb: &ProgressBar) {
        // Simple IDOR check: look for numeric parameters and try to decrement them
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();

        for (key, value) in query_pairs {
            if let Ok(id) = value.parse::<i32>() {
                if id > 0 {
                    let new_id = id - 1;
                    let mut new_url = url.clone();

                    // Rebuild query with modified ID
                    let mut new_query = url.query_pairs().into_owned().collect::<Vec<_>>();
                    for (k, v) in &mut new_query {
                        if k == &key {
                            *v = new_id.to_string();
                        }
                    }

                    {
                        let mut serializer = new_url.query_pairs_mut();
                        serializer.clear();
                        for (k, v) in new_query {
                            serializer.append_pair(&k, &v);
                        }
                    }

                    self.rate_limiter.wait().await;
                    if let Ok(response) = self.client.get(new_url.clone()).send().await {
                        // Heuristic: If we get a 200 OK and the length is different (or we can't check length easily without a baseline), report it.
                        // For now, just reporting 200 OK on a modified ID as a potential issue.
                        // A better check would be to compare with the original response.
                        if response.status().is_success() {
                            let vuln = AccessControlVulnerability {
                                url: new_url,
                                vuln_type: "IDOR (Potential)".to_string(),
                                description: format!(
                                    "Accessible resource with modified ID parameter '{}': {} -> {}",
                                    key, id, new_id
                                ),
                                severity: "Medium".to_string(),
                                payload: format!("{}={}", key, new_id),
                            };
                            self.reporter.report_access_control(&vuln);
                        }
                    }
                }
            }
        }
        pb.inc(1);
    }

    async fn check_method_override(&self, url: &Url, pb: &ProgressBar) {
        let methods = vec![
            reqwest::Method::POST,
            reqwest::Method::PUT,
            reqwest::Method::DELETE,
            reqwest::Method::PATCH,
        ];

        for method in methods {
            self.rate_limiter.wait().await;
            if let Ok(response) = self
                .client
                .request(method.clone(), url.clone())
                .send()
                .await
            {
                // If we get a success code on a method that usually shouldn't work (like PUT/DELETE on a public page), report it.
                // Or if we get a 405 on GET but 200 on POST (unlikely for GET-only, but possible for API endpoints).
                // Here we just check for unexpected success status codes.
                if response.status().is_success()
                    || response.status() == reqwest::StatusCode::CREATED
                    || response.status() == reqwest::StatusCode::NO_CONTENT
                {
                    let vuln = AccessControlVulnerability {
                        url: url.clone(),
                        vuln_type: "HTTP Method Override".to_string(),
                        description: format!("Endpoint accepts {} method", method),
                        severity: "Low".to_string(),
                        payload: method.to_string(),
                    };
                    self.reporter.report_access_control(&vuln);
                }
            }
        }
        pb.inc(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporter::Reporter;
    use std::time::Duration;
    use tempfile::TempDir;

    fn create_test_scanner(url: Url, reporter: &Arc<Reporter>) -> AccessControlScanner {
        AccessControlScanner::new(
            url.clone(),
            vec![url], // Discovered URLs
            reporter,
            Arc::new(RateLimiter::new(Duration::from_millis(0))),
        )
    }

    fn create_test_reporter() -> (Arc<Reporter>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let url = Url::parse("http://example.com").unwrap();
        let reporter = Reporter::new(url).with_output_dir(temp_dir.path().to_path_buf());
        (Arc::new(reporter), temp_dir)
    }

    #[tokio::test]
    async fn test_check_forced_browsing() {
        let mut server = mockito::Server::new_async().await;
        let url = Url::parse(&server.url()).unwrap();

        // Create reporter with the actual server URL
        let temp_dir = TempDir::new().unwrap();
        let reporter = Reporter::new(url.clone()).with_output_dir(temp_dir.path().to_path_buf());
        let reporter = Arc::new(reporter);
        let mut scanner = create_test_scanner(url.clone(), &reporter);

        // Mock a sensitive path
        let _m = server.mock("GET", "/admin").with_status(200).create();

        scanner.load_sensitive_paths(vec!["/admin".to_string()]);

        let pb = ProgressBar::hidden();
        scanner.check_forced_browsing(&pb).await;

        // Verify report file exists
        let report_path = temp_dir
            .path()
            .join(format!(
                "{}_{}",
                url.host_str().unwrap().replace('.', "_"),
                url.port_or_known_default().unwrap()
            ))
            .join("Access-Control-output.md");
        assert!(report_path.exists());
    }

    #[tokio::test]
    async fn test_check_idor() {
        let mut server = mockito::Server::new_async().await;
        let url = Url::parse(&format!("{}/profile?id=100", server.url())).unwrap();

        // Create reporter with the actual server URL
        let temp_dir = TempDir::new().unwrap();
        let reporter = Reporter::new(url.clone()).with_output_dir(temp_dir.path().to_path_buf());
        let reporter = Arc::new(reporter);
        let scanner = create_test_scanner(url.clone(), &reporter);

        // Mock the decremented ID endpoint
        let _m = server
            .mock("GET", "/profile?id=99")
            .with_status(200)
            .create();

        let pb = ProgressBar::hidden();
        scanner.check_idor(&url, &pb).await;

        // Verify report file exists
        let report_path = temp_dir
            .path()
            .join(format!(
                "{}_{}",
                url.host_str().unwrap().replace('.', "_"),
                url.port_or_known_default().unwrap()
            ))
            .join("Access-Control-output.md");
        assert!(report_path.exists());
    }

    #[tokio::test]
    async fn test_check_method_override() {
        let mut server = mockito::Server::new_async().await;
        let url = Url::parse(&format!("{}/api/resource", server.url())).unwrap();

        // Create reporter with the actual server URL
        let temp_dir = TempDir::new().unwrap();
        let reporter = Reporter::new(url.clone()).with_output_dir(temp_dir.path().to_path_buf());
        let reporter = Arc::new(reporter);
        let scanner = create_test_scanner(url.clone(), &reporter);

        // Mock a PUT request success
        let _m = server
            .mock("PUT", "/api/resource")
            .with_status(200)
            .create();

        let pb = ProgressBar::hidden();
        scanner.check_method_override(&url, &pb).await;

        // Verify report file exists
        let report_path = temp_dir
            .path()
            .join(format!(
                "{}_{}",
                url.host_str().unwrap().replace('.', "_"),
                url.port_or_known_default().unwrap()
            ))
            .join("Access-Control-output.md");
        assert!(report_path.exists());
    }
}
