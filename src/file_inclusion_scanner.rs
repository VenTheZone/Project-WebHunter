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

    pub async fn scan(
        &self,
        pb: &ProgressBar,
    ) -> Result<(), reqwest::Error> {
        self.scan_urls(pb).await?;
        self.scan_forms(pb).await?;
        Ok(())
    }

    async fn scan_urls(
        &self,
        pb: &ProgressBar,
    ) -> Result<(), reqwest::Error> {
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
                            println!("[+] File Inclusion Found: {} in {}", vuln.payload, vuln.parameter);
                            self.reporter.report_file_inclusion(&vuln);
                            continue 'param_loop;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn scan_forms(
        &self,
        pb: &ProgressBar,
    ) -> Result<(), reqwest::Error> {
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
                            println!("[+] File Inclusion Found: {} in {}", vuln.payload, vuln.parameter);
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
