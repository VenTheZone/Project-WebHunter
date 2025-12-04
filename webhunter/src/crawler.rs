use crate::form::{Form, FormInput};
use crate::rate_limiter::RateLimiter;
use indicatif::ProgressBar;
use rand::seq::SliceRandom;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead};
use std::sync::Arc;
use url::Url;

pub struct Crawler {
    target_url: Url,
    visited_urls: HashSet<Url>,
    user_agents: Vec<String>,
    http_headers: Vec<(String, String)>,
    forms: Vec<Form>,
    rate_limiter: Arc<RateLimiter>,
}

impl Crawler {
    pub fn new(target_url: Url, rate_limiter: Arc<RateLimiter>) -> Self {
        Self {
            target_url,
            visited_urls: HashSet::new(),
            user_agents: Self::load_list("wordlists/user_agents.txt"),
            http_headers: Self::load_header_payloads(),
            forms: Vec::new(),
            rate_limiter,
        }
    }

    fn load_list(path: &str) -> Vec<String> {
        let mut list = Vec::new();
        if let Ok(file) = fs::File::open(path) {
            let reader = io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                list.push(line);
            }
        }
        list
    }

    fn load_header_payloads() -> Vec<(String, String)> {
        let mut payloads = Vec::new();
        if let Ok(file) = fs::File::open("wordlists/http_headers.txt") {
            let reader = io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    payloads.push((parts[0].to_string(), parts[1].trim().to_string()));
                }
            }
        }
        payloads
    }

    pub async fn crawl(
        &mut self,
        pb: &ProgressBar,
    ) -> Result<(Vec<Url>, Vec<Form>), reqwest::Error> {
        let mut urls_to_visit = vec![self.target_url.clone()];
        let mut found_urls = vec![];
        let max_depth = 3;

        for depth in 0..max_depth {
            let mut next_urls = HashSet::new();
            let urls_at_current_depth = urls_to_visit.clone();
            urls_to_visit.clear();

            for url in urls_at_current_depth {
                if self.visited_urls.contains(&url) {
                    continue;
                }

                pb.set_message(format!("Crawling: {}", url));
                self.visited_urls.insert(url.clone());
                found_urls.push(url.clone());

                let client = reqwest::Client::new();
                let user_agent = &self.user_agents[depth % self.user_agents.len()];
                let mut request = client.get(url.clone()).header("User-Agent", user_agent);

                if let Some((header_name, header_value)) =
                    self.http_headers.choose(&mut rand::thread_rng())
                {
                    request = request.header(header_name, header_value);
                }

                self.rate_limiter.wait().await;
                let response = match request.send().await {
                    Ok(resp) => {
                        if resp.status() == reqwest::StatusCode::NOT_FOUND {
                            continue;
                        }
                        resp
                    }
                    Err(_) => continue,
                };

                pb.inc(1);

                if let Ok(body) = response.text().await {
                    let document = Html::parse_document(&body);
                    let selector = Selector::parse("a, img, link, script").unwrap();

                    for element in document.select(&selector) {
                        let href = match element.value().name() {
                            "a" | "link" => element.value().attr("href"),
                            "img" | "script" => element.value().attr("src"),
                            _ => None,
                        };

                        if let Some(href) = href {
                            if let Ok(mut new_url) = url.join(href) {
                                if new_url.domain() == self.target_url.domain()
                                    && (new_url.scheme() == "http" || new_url.scheme() == "https")
                                {
                                    new_url.set_fragment(None);
                                    if !self.visited_urls.contains(&new_url) {
                                        next_urls.insert(new_url);
                                    }
                                }
                            }
                        }
                    }

                    let form_selector = Selector::parse("form").unwrap();
                    let input_selector = Selector::parse("input").unwrap();
                    for form_element in document.select(&form_selector) {
                        let action = form_element
                            .value()
                            .attr("action")
                            .unwrap_or("")
                            .to_string();
                        let method = form_element
                            .value()
                            .attr("method")
                            .unwrap_or("get")
                            .to_string();
                        let mut inputs = Vec::new();
                        for input_element in form_element.select(&input_selector) {
                            let name = input_element.value().attr("name").unwrap_or("").to_string();
                            if name.is_empty() {
                                continue;
                            }
                            let value = input_element
                                .value()
                                .attr("value")
                                .unwrap_or("")
                                .to_string();
                            let input_type = input_element
                                .value()
                                .attr("type")
                                .unwrap_or("text")
                                .to_string();
                            inputs.push(FormInput {
                                name,
                                value,
                                input_type,
                            });
                        }
                        self.forms.push(Form {
                            action,
                            method,
                            inputs,
                            url: url.clone(),
                        });
                    }
                }
            }
            urls_to_visit.extend(next_urls);
        }

        Ok((found_urls, self.forms.clone()))
    }
}
