use indicatif::ProgressBar;
use serde::Deserialize;
use std::process::{Command, Stdio};
use url::Url;

#[derive(Debug, Deserialize)]
struct FeroxResponse {
    url: String,
    status: u16,
    content_length: u64,
}

pub struct DirScanner<'a> {
    target_url: Url,
    wordlist_path: Option<String>,
    pb: &'a ProgressBar,
}

impl<'a> DirScanner<'a> {
    pub fn new(
        target_url: Url,
        pb: &'a ProgressBar,
        wordlist_path: Option<String>,
    ) -> Self {
        Self {
            target_url,
            wordlist_path,
            pb,
        }
    }

    pub async fn scan(&self) -> Result<Vec<(Url, u16, u64)>, std::io::Error> {
        let wordlist = self
            .wordlist_path
            .clone()
            .unwrap_or("default_wordlist.txt".to_string());

        let args = vec![
            "-u",
            self.target_url.as_str(),
            "--json",
            "--silent",
            "-w",
            &wordlist,
        ];

        self.pb.set_message("Running feroxbuster...");
        let output = match Command::new("feroxbuster")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child.wait_with_output()?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "feroxbuster not found. Please install it and try again.",
                ));
            }
        };

        self.pb.finish_with_message("Feroxbuster scan complete");

        let mut results = Vec::new();
        let json_output = String::from_utf8_lossy(&output.stdout);

        for line in json_output.lines() {
            if let Ok(response) = serde_json::from_str::<FeroxResponse>(line) {
                if response.status != 404 {
                    if let Ok(url) = Url::parse(&response.url) {
                        results.push((url, response.status, response.content_length));
                    }
                }
            }
        }

        Ok(results)
    }
}
