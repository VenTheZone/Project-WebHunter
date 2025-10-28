use crate::form::Form;
use indicatif::ProgressBar;
use reqwest;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct FileInclusionVulnerability {
    pub url: Url,
    pub parameter: String,
    pub payload: String,
    pub vuln_type: String,
}

use std::fs;
use std::io::{self, BufRead};

pub struct FileInclusionScanner {
    target_urls: Vec<Url>,
    forms: Vec<Form>,
    payloads: Vec<String>,
}

impl FileInclusionScanner {
    pub fn new(target_urls: Vec<Url>, forms: Vec<Form>) -> Self {
        let mut payloads = Vec::new();
        if let Ok(paths) = fs::read_dir("wordlists/file_inclusion") {
            println!("Reading payloads from wordlists/file_inclusion...");
            for path in paths {
                if let Ok(path) = path {
                    if let Some(extension) = path.path().extension() {
                        if extension == "txt" {
                            if let Ok(file) = fs::File::open(path.path()) {
                                let reader = io::BufReader::new(file);
                                for line in reader.lines() {
                                    if let Ok(line) = line {
                                        payloads.push(line);
                                    }
                                }
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
        }
    }

    pub fn payloads_count(&self) -> usize {
        self.payloads.len()
    }

    pub async fn scan(
        &self,
        pb: &ProgressBar,
    ) -> Result<Vec<FileInclusionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = self.scan_urls(pb).await?;
        vulnerabilities.extend(self.scan_forms(pb).await?);
        Ok(vulnerabilities)
    }

    async fn scan_urls(
        &self,
        pb: &ProgressBar,
    ) -> Result<Vec<FileInclusionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = Vec::new();
        let client = reqwest::Client::new();

        for url in &self.target_urls {
            if url.query_pairs().count() == 0 {
                continue;
            }

            for payload in &self.payloads {
                let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
                for i in 0..query_pairs.len() {
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

                    let response = client.get(new_url.clone()).send().await?;
                    if let Ok(body) = response.text().await {
                        if let Some(vuln_type) = self.is_vulnerable(&body, payload) {
                            vulnerabilities.push(FileInclusionVulnerability {
                                url: url.clone(),
                                parameter: tested_param,
                                payload: payload.to_string(),
                                vuln_type,
                            });
                        }
                    }
                }
                pb.inc(1);
                sleep(Duration::from_millis(50)).await;
            }
        }
        Ok(vulnerabilities)
    }

    async fn scan_forms(
        &self,
        pb: &ProgressBar,
    ) -> Result<Vec<FileInclusionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = Vec::new();
        let client = reqwest::Client::new();

        for form in &self.forms {
            for payload in &self.payloads {
                for i in 0..form.inputs.len() {
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
                    let response = if form.method.to_lowercase() == "post" {
                        client.post(action_url).form(&form_data).send().await?
                    } else {
                        client.get(action_url).query(&form_data).send().await?
                    };

                    if let Ok(body) = response.text().await {
                        if let Some(vuln_type) = self.is_vulnerable(&body, payload) {
                            vulnerabilities.push(FileInclusionVulnerability {
                                url: form.url.clone(),
                                parameter: tested_param,
                                payload: payload.to_string(),
                                vuln_type,
                            });
                        }
                    }
                }
                pb.inc(1);
                sleep(Duration::from_millis(50)).await;
            }
        }

        Ok(vulnerabilities)
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
