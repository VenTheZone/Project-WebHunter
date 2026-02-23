use crate::reporter::Reporter;
use indicatif::ProgressBar;
use serde::Deserialize;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;
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
    reporter: &'a Arc<Reporter>,
}

impl<'a> DirScanner<'a> {
    pub fn new(
        target_url: Url,
        pb: &'a ProgressBar,
        wordlist_path: Option<String>,
        reporter: &'a Arc<Reporter>,
    ) -> Self {
        Self {
            target_url,
            wordlist_path,
            pb,
            reporter,
        }
    }

    pub async fn scan(&self) -> Result<(), std::io::Error> {
        let wordlist = self
            .wordlist_path
            .clone()
            .unwrap_or("webhunter/default_wordlist.txt".to_string());

        let args = vec![
            "-u",
            self.target_url.as_str(),
            "--json",
            "--silent",
            "-w",
            &wordlist,
        ];

        self.pb.set_message("Running feroxbuster...");
        let mut child = Command::new("feroxbuster")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let line = line?;
                if let Ok(response) = serde_json::from_str::<FeroxResponse>(&line) {
                    if response.status != 404 {
                        if let Ok(url) = Url::parse(&response.url) {
                            println!(
                                "[+] Open Directory Found: {} (Status: {}, Size: {})",
                                url, response.status, response.content_length
                            );
                            self.reporter.report_directory(
                                &url,
                                response.status,
                                response.content_length,
                            );
                        }
                    }
                }
            }
        }

        child.wait()?;
        self.pb.finish_with_message("Feroxbuster scan complete");

        Ok(())
    }
}
