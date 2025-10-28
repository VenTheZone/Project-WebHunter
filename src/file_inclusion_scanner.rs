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

pub struct FileInclusionScanner {
    target_urls: Vec<Url>,
    forms: Vec<Form>,
    lfi_payloads: Vec<&'static str>,
    rfi_payloads: Vec<&'static str>,
}

impl FileInclusionScanner {
    pub fn new(target_urls: Vec<Url>, forms: Vec<Form>) -> Self {
        Self {
            target_urls,
            forms,
            lfi_payloads: vec![
                "../../../../../../../../etc/passwd",
                "../../../../../../../../windows/win.ini",
            ],
            rfi_payloads: vec!["http://google.com/robots.txt"],
        }
    }

    pub fn payloads_count(&self) -> usize {
        self.lfi_payloads.len() + self.rfi_payloads.len()
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

            for payload in self.lfi_payloads.iter().chain(self.rfi_payloads.iter()) {
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
            for payload in self.lfi_payloads.iter().chain(self.rfi_payloads.iter()) {
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
        if self.lfi_payloads.contains(&payload) {
            if body.contains("root:x:0:0") || body.contains("[fonts]") {
                return Some("LFI".to_string());
            }
        } else if self.rfi_payloads.contains(&payload) {
            if body.contains("User-agent: *") {
                return Some("RFI".to_string());
            }
        }
        None
    }
}
