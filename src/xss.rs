use crate::form::Form;
use indicatif::ProgressBar;
use reqwest;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

#[derive(Debug)]
pub struct Vulnerability {
    pub url: Url,
    pub parameter: String,
    pub payload: String,
    pub vuln_type: String,
    pub severity: String,
}

pub struct XssScanner {
    target_urls: Vec<Url>,
    forms: Vec<Form>,
    payloads: Vec<String>,
}

use std::fs;
use std::io::{self, BufRead};

impl XssScanner {
    pub fn new(target_urls: Vec<Url>, forms: Vec<Form>) -> Self {
        let mut payloads = Vec::new();
        if let Ok(paths) = fs::read_dir("wordlists/xss") {
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

    pub async fn scan(&self, pb: &ProgressBar) -> Result<Vec<Vulnerability>, reqwest::Error> {
        let mut vulnerabilities = self.scan_urls(pb).await?;
        vulnerabilities.extend(self.scan_forms(pb).await?);
        Ok(vulnerabilities)
    }

    async fn scan_urls(&self, pb: &ProgressBar) -> Result<Vec<Vulnerability>, reqwest::Error> {
        let mut vulnerabilities = vec![];
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
                    if response.status() == reqwest::StatusCode::NOT_FOUND {
                        continue;
                    }
                    if let Ok(body) = response.text().await {
                        if self.is_vulnerable(&body, payload) {
                            vulnerabilities.push(Vulnerability {
                                url: url.clone(),
                                parameter: tested_param,
                                payload: payload.clone(),
                                vuln_type: "Reflected".to_string(),
                                severity: "Medium".to_string(),
                            });
                        }
                    }
                    sleep(Duration::from_millis(50)).await;
                    pb.inc(1);
                }
            }
        }
        Ok(vulnerabilities)
    }

    async fn scan_forms(&self, pb: &ProgressBar) -> Result<Vec<Vulnerability>, reqwest::Error> {
        let mut vulnerabilities = vec![];
        let client = reqwest::Client::new();

        for form in &self.forms {
            for payload in &self.payloads {
                for i in 0..form.inputs.len() {
                    let mut form_data = HashMap::new();
                    let mut tested_param = String::new();
                    for (j, input) in form.inputs.iter().enumerate() {
                        if i == j {
                            form_data.insert(input.name.clone(), payload.clone());
                            tested_param = input.name.clone();
                        } else {
                            form_data.insert(input.name.clone(), input.value.clone());
                        }
                    }

                    let mut action_url = match form.url.join(&form.action) {
                        Ok(url) => url,
                        Err(_) => continue,
                    };
                    let original_query = action_url.query_pairs().into_owned().collect::<Vec<(String, String)>>();

                    let response_res = if form.method.to_lowercase() == "post" {
                        let mut post_form_data = form_data.clone();
                        for (key, value) in original_query {
                            post_form_data.insert(key, value);
                        }
                        client.post(action_url.clone()).form(&post_form_data).send().await
                    } else {
                        for (key, value) in original_query {
                            action_url.query_pairs_mut().append_pair(&key, &value);
                        }
                        client.get(action_url.clone()).query(&form_data).send().await
                    };

                    if let Ok(response) = response_res {
                        if response.status() == reqwest::StatusCode::NOT_FOUND {
                            continue;
                        }
                        if let Ok(body) = response.text().await {
                            if self.is_vulnerable(&body, payload) {
                                vulnerabilities.push(Vulnerability {
                                    url: form.url.clone(),
                                    parameter: tested_param.clone(),
                                    payload: payload.clone(),
                                    vuln_type: "Reflected".to_string(),
                                    severity: "Medium".to_string(),
                                });
                            }
                        }
                    }

                    // Check for stored XSS by visiting the action URL after submission
                    let response_res = client.get(action_url.clone()).send().await;
                    if let Ok(response) = response_res {
                        if response.status() == reqwest::StatusCode::NOT_FOUND {
                            continue;
                        }
                        if let Ok(body) = response.text().await {
                            if self.is_vulnerable(&body, payload) {
                                vulnerabilities.push(Vulnerability {
                                    url: form.url.clone(),
                                    parameter: tested_param.clone(),
                                    payload: payload.clone(),
                                    vuln_type: "Stored".to_string(),
                                    severity: "High".to_string(),
                                });
                            }
                        }
                    }

                    sleep(Duration::from_millis(50)).await;
                    pb.inc(1);
                }
            }
        }
        Ok(vulnerabilities)
    }

    fn is_vulnerable(&self, body: &str, payload: &str) -> bool {
        let sanitized_payload = payload.replace("'", "\"");
        if body.contains(&sanitized_payload) {
            return true;
        }

        let document = scraper::Html::parse_document(body);
        for element in document.select(&scraper::Selector::parse("*").unwrap()) {
            for attr in element.value().attrs() {
                if attr.1.contains(payload) {
                    return true;
                }
            }
        }
        false
    }
}
