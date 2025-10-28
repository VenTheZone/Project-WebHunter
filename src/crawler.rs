use crate::form::{Form, FormInput};
use indicatif::ProgressBar;
use reqwest;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

pub struct Crawler {
    target_url: Url,
    visited_urls: HashSet<Url>,
    user_agents: Vec<&'static str>,
    forms: Vec<Form>,
}

impl Crawler {
    pub fn new(target_url: Url) -> Self {
        Self {
            target_url,
            visited_urls: HashSet::new(),
            user_agents: vec![
                "Googlebot",
                "Bingbot",
                "Yahoo! Slurp",
                "DuckDuckBot",
                "Facebot",
                "curl/7.68.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            ],
            forms: Vec::new(),
        }
    }

    pub async fn crawl(
        &mut self,
        pb: &ProgressBar,
    ) -> Result<(Vec<Url>, Vec<Form>), reqwest::Error> {
        let mut urls_to_visit = vec![self.target_url.clone()];
        let mut found_urls = vec![];
        let max_depth = 2;

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
                let user_agent = self.user_agents[depth % self.user_agents.len()];
                let response = match client
                    .get(url.clone())
                    .header("User-Agent", user_agent)
                    .send()
                    .await
                {
                    Ok(resp) => resp,
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
                        let action = form_element.value().attr("action").unwrap_or("").to_string();
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
                            let value = input_element.value().attr("value").unwrap_or("").to_string();
                            inputs.push(FormInput {
                                name,
                                value,
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
                sleep(Duration::from_millis(200)).await;
            }
            urls_to_visit.extend(next_urls);
        }

        Ok((found_urls, self.forms.clone()))
    }
}
