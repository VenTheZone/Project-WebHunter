use crate::form::Form;
use indicatif::ProgressBar;
use reqwest;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct SqlInjectionVulnerability {
    pub url: Url,
    pub parameter: String,
    pub payload: String,
    pub vuln_type: String,
}

pub struct SqlInjectionScanner {
    target_urls: Vec<Url>,
    forms: Vec<Form>,
    error_based_payloads: Vec<&'static str>,
    boolean_based_payloads: Vec<(&'static str, &'static str)>,
    time_based_payloads: Vec<&'static str>,
}

impl SqlInjectionScanner {
    pub fn new(target_urls: Vec<Url>, forms: Vec<Form>) -> Self {
        Self {
            target_urls,
            forms,
            error_based_payloads: vec![
                "'", "\"", "`", "')", "\")", "`)", "'))", "\"))", "`))",
                "OR 1=1", "OR 1=0", "AND 1=1", "AND 1=0",
            ],
            boolean_based_payloads: vec![
                (" AND 1=1", " AND 1=2"),
                (" OR 1=1", " OR 1=2"),
                (" and 1 in (1)", " and 1 in (2)"),
            ],
            time_based_payloads: vec![
                "AND (SELECT * FROM (SELECT(SLEEP(5)))b)", // MySQL
                "OR pg_sleep(5)",                          // PostgreSQL
                "AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',5)", // Oracle
                "WAITFOR DELAY '0:0:5'",                   // MSSQL
            ],
        }
    }

    pub fn payloads_count(&self) -> usize {
        self.error_based_payloads.len()
            + self.boolean_based_payloads.len() * 2
            + self.time_based_payloads.len()
    }

    pub async fn scan(
        &self,
        pb: &ProgressBar,
    ) -> Result<Vec<SqlInjectionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = self.scan_urls(pb).await?;
        vulnerabilities.extend(self.scan_forms(pb).await?);
        Ok(vulnerabilities)
    }

    async fn scan_urls(
        &self,
        pb: &ProgressBar,
    ) -> Result<Vec<SqlInjectionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = Vec::new();
        let client = reqwest::Client::new();

        for url in &self.target_urls {
            if url.query_pairs().count() == 0 {
                continue;
            }

            for payload in &self.error_based_payloads {
                vulnerabilities.extend(
                    self.test_error_based(&client, url.clone(), payload, pb)
                        .await?,
                );
            }

            for (true_payload, false_payload) in &self.boolean_based_payloads {
                vulnerabilities.extend(
                    self.test_boolean_based(&client, url.clone(), true_payload, false_payload, pb)
                        .await?,
                );
            }

            for payload in &self.time_based_payloads {
                vulnerabilities.extend(
                    self.test_time_based(&client, url.clone(), payload, pb)
                        .await?,
                );
            }
        }
        Ok(vulnerabilities)
    }

    async fn test_boolean_based(
        &self,
        client: &reqwest::Client,
        url: Url,
        true_payload: &str,
        false_payload: &str,
        pb: &ProgressBar,
    ) -> Result<Vec<SqlInjectionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = Vec::new();
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();

        for i in 0..query_pairs.len() {
            let mut true_query_parts = Vec::new();
            let mut false_query_parts = Vec::new();
            let mut tested_param = String::new();

            for (j, (key, value)) in query_pairs.iter().enumerate() {
                if i == j {
                    true_query_parts.push(format!("{}={}{}", key, value, true_payload));
                    false_query_parts.push(format!("{}={}{}", key, value, false_payload));
                    tested_param = key.clone();
                } else {
                    true_query_parts.push(format!("{}={}", key, value));
                    false_query_parts.push(format!("{}={}", key, value));
                }
            }

            let true_query = true_query_parts.join("&");
            let false_query = false_query_parts.join("&");

            let mut true_url = url.clone();
            true_url.set_query(Some(&true_query));

            let mut false_url = url.clone();
            false_url.set_query(Some(&false_query));

            let true_response = client.get(true_url).send().await?;
            let false_response = client.get(false_url).send().await?;

            if let (Ok(true_body), Ok(false_body)) = (true_response.text().await, false_response.text().await) {
                if true_body != false_body {
                    vulnerabilities.push(SqlInjectionVulnerability {
                        url: url.clone(),
                        parameter: tested_param,
                        payload: format!("{} / {}", true_payload, false_payload),
                        vuln_type: "Boolean-Based".to_string(),
                    });
                }
            }
            pb.inc(2);
            sleep(Duration::from_millis(100)).await;
        }
        Ok(vulnerabilities)
    }

    async fn test_time_based(
        &self,
        client: &reqwest::Client,
        url: Url,
        payload: &str,
        pb: &ProgressBar,
    ) -> Result<Vec<SqlInjectionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = Vec::new();
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();

        for i in 0..query_pairs.len() {
            let mut new_query_parts = Vec::new();
            let mut tested_param = String::new();

            for (j, (key, value)) in query_pairs.iter().enumerate() {
                if i == j {
                    new_query_parts.push(format!("{}={}{}", key, value, payload));
                    tested_param = key.clone();
                } else {
                    new_query_parts.push(format!("{}={}", key, value));
                }
            }

            let new_query = new_query_parts.join("&");
            let mut new_url = url.clone();
            new_url.set_query(Some(&new_query));

            let start = Instant::now();
            let _ = client.get(new_url.clone()).send().await?;
            let duration = start.elapsed();

            if duration > Duration::from_secs(5) {
                vulnerabilities.push(SqlInjectionVulnerability {
                    url: url.clone(),
                    parameter: tested_param,
                    payload: payload.to_string(),
                    vuln_type: "Time-Based".to_string(),
                });
            }
            pb.inc(1);
            sleep(Duration::from_millis(50)).await;
        }
        Ok(vulnerabilities)
    }

    async fn scan_forms(
        &self,
        pb: &ProgressBar,
    ) -> Result<Vec<SqlInjectionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = Vec::new();
        let client = reqwest::Client::new();

        for form in &self.forms {
            for payload in &self.error_based_payloads {
                vulnerabilities.extend(
                    self.test_form_error_based(&client, form, payload, pb)
                        .await?,
                );
            }

            for (true_payload, false_payload) in &self.boolean_based_payloads {
                vulnerabilities.extend(
                    self.test_form_boolean_based(
                        &client,
                        form,
                        true_payload,
                        false_payload,
                        pb,
                    )
                    .await?,
                );
            }

            for payload in &self.time_based_payloads {
                vulnerabilities.extend(
                    self.test_form_time_based(&client, form, payload, pb)
                        .await?,
                );
            }
        }
        Ok(vulnerabilities)
    }

    async fn test_form_error_based(
        &self,
        client: &reqwest::Client,
        form: &Form,
        payload: &str,
        pb: &ProgressBar,
    ) -> Result<Vec<SqlInjectionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = Vec::new();
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

            let action_url = match form.url.join(&form.action) {
                Ok(url) => url,
                Err(_) => continue,
            };
            let response = if form.method.to_lowercase() == "post" {
                client.post(action_url).form(&form_data).send().await?
            } else {
                client.get(action_url).query(&form_data).send().await?
            };

            if let Ok(body) = response.text().await {
                if self.is_error_based_vulnerable(&body) {
                    vulnerabilities.push(SqlInjectionVulnerability {
                        url: form.url.clone(),
                        parameter: tested_param,
                        payload: payload.to_string(),
                        vuln_type: "Error-Based".to_string(),
                    });
                }
            }
            pb.inc(1);
            sleep(Duration::from_millis(50)).await;
        }
        Ok(vulnerabilities)
    }

    async fn test_form_boolean_based(
        &self,
        client: &reqwest::Client,
        form: &Form,
        true_payload: &str,
        false_payload: &str,
        pb: &ProgressBar,
    ) -> Result<Vec<SqlInjectionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = Vec::new();
        for i in 0..form.inputs.len() {
            let mut true_form_data = HashMap::new();
            let mut false_form_data = HashMap::new();
            let mut tested_param = String::new();
            for (j, input) in form.inputs.iter().enumerate() {
                if i == j {
                    true_form_data.insert(input.name.clone(), true_payload.to_string());
                    false_form_data.insert(input.name.clone(), false_payload.to_string());
                    tested_param = input.name.clone();
                } else {
                    true_form_data.insert(input.name.clone(), input.value.clone());
                    false_form_data.insert(input.name.clone(), input.value.clone());
                }
            }

            let action_url = match form.url.join(&form.action) {
                Ok(url) => url,
                Err(_) => continue,
            };
            let true_response = if form.method.to_lowercase() == "post" {
                client
                    .post(action_url.clone())
                    .form(&true_form_data)
                    .send()
                    .await?
            } else {
                client
                    .get(action_url.clone())
                    .query(&true_form_data)
                    .send()
                    .await?
            };

            let false_response = if form.method.to_lowercase() == "post" {
                client.post(action_url).form(&false_form_data).send().await?
            } else {
                client.get(action_url).query(&false_form_data).send().await?
            };

            if let (Ok(true_body), Ok(false_body)) = (true_response.text().await, false_response.text().await) {
                if true_body != false_body {
                    vulnerabilities.push(SqlInjectionVulnerability {
                        url: form.url.clone(),
                        parameter: tested_param,
                        payload: format!("{} / {}", true_payload, false_payload),
                        vuln_type: "Boolean-Based".to_string(),
                    });
                }
            }
            pb.inc(2);
            sleep(Duration::from_millis(100)).await;
        }
        Ok(vulnerabilities)
    }

    async fn test_form_time_based(
        &self,
        client: &reqwest::Client,
        form: &Form,
        payload: &str,
        pb: &ProgressBar,
    ) -> Result<Vec<SqlInjectionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = Vec::new();
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

            let action_url = match form.url.join(&form.action) {
                Ok(url) => url,
                Err(_) => continue,
            };
            let start = Instant::now();
            if form.method.to_lowercase() == "post" {
                let _ = client.post(action_url).form(&form_data).send().await?;
            } else {
                let _ = client.get(action_url).query(&form_data).send().await?;
            };
            let duration = start.elapsed();

            if duration > Duration::from_secs(5) {
                vulnerabilities.push(SqlInjectionVulnerability {
                    url: form.url.clone(),
                    parameter: tested_param,
                    payload: payload.to_string(),
                    vuln_type: "Time-Based".to_string(),
                });
            }
            pb.inc(1);
            sleep(Duration::from_millis(50)).await;
        }
        Ok(vulnerabilities)
    }

    async fn test_error_based(
        &self,
        client: &reqwest::Client,
        url: Url,
        payload: &str,
        pb: &ProgressBar,
    ) -> Result<Vec<SqlInjectionVulnerability>, reqwest::Error> {
        let mut vulnerabilities = Vec::new();
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();

        for i in 0..query_pairs.len() {
            let mut new_query_parts = Vec::new();
            let mut tested_param = String::new();

            for (j, (key, value)) in query_pairs.iter().enumerate() {
                if i == j {
                    new_query_parts.push(format!("{}={}{}", key, value, payload));
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
                if self.is_error_based_vulnerable(&body) {
                    vulnerabilities.push(SqlInjectionVulnerability {
                        url: url.clone(),
                        parameter: tested_param,
                        payload: payload.to_string(),
                        vuln_type: "Error-Based".to_string(),
                    });
                }
            }
            pb.inc(1);
            sleep(Duration::from_millis(50)).await;
        }
        Ok(vulnerabilities)
    }

    fn is_error_based_vulnerable(&self, body: &str) -> bool {
        let error_patterns = [
            "You have an error in your SQL syntax",
            "Unclosed quotation mark",
            "Warning: mysql_fetch_array()",
        ];
        error_patterns.iter().any(|&p| body.contains(p))
    }
}
