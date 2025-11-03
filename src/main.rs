use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Input, Select};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Arc;
use tokio::sync::Semaphore;
use url::Url;
use std::time::Duration;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use colored::*;

mod crawler;
mod dir_scanner;
mod form;
mod reporter;
mod xss;
mod dependency_manager;
mod file_inclusion_scanner;
mod sql_injection_scanner;
mod animation;
mod bypass_403;
mod snapshot;
mod rate_limiter;

struct Config {
    request_delay: Duration,
}

fn configure_rate_limit() -> Config {
    loop {
        let rps_input: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter Requests Per Second (RPS)")
            .default("5".into())
            .interact_text()
            .unwrap();

        match rps_input.trim().parse::<u64>() {
            Ok(mut rps) => {
                if rps == 0 {
                    println!("{}", "RPS cannot be 0. Please enter a valid number.".red());
                    continue;
                }
                if rps > 100 {
                    println!("{}", "RPS is capped at 100 to prevent overwhelming the target server.".yellow());
                    rps = 100;
                }
                println!("Running at {} RPS.", rps);
                if rps > 5 {
                    println!("{}", "[WARNING] Rates above 5 RPS may get your IP blacklisted. Proceed with caution.".yellow());
                }
                let delay_ms = 1000 / rps;
                return Config {
                    request_delay: Duration::from_millis(delay_ms),
                };
            }
            Err(_) => {
                println!("{}", "Invalid input. Please enter a number.".red());
            }
        }
    }
}

async fn crawl_target(
    url: Url,
    m: &MultiProgress,
    sty: &ProgressStyle,
    rate_limiter: &Arc<rate_limiter::RateLimiter>,
) -> Result<(Vec<Url>, Vec<form::Form>), reqwest::Error> {
    let mut crawler = crawler::Crawler::new(url.clone(), Arc::clone(rate_limiter));
    let pb_crawl = m.add(ProgressBar::new(100));
    pb_crawl.set_style(sty.clone());

    match crawler.crawl(&pb_crawl).await {
        Ok((urls, forms)) => {
            pb_crawl.finish_with_message("Crawling complete");
            Ok((urls, forms))
        }
        Err(e) => {
            pb_crawl.finish_with_message(format!("Crawling failed: {}", e));
            eprintln!("Error crawling: {}", e);
            Err(e)
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = "A comprehensive web vulnerability scanner.")]
struct Cli {
    /// The target website URL to scan
    #[arg(short, long)]
    target: Option<String>,

    /// Path to a file containing a list of target URLs
    #[arg(long)]
    target_list: Option<String>,

    /// The type of scanner to use (xss, dir, file, sql, bypass)
    #[arg(short, long)]
    scanner: Option<String>,

    /// Path to a custom wordlist file
    #[arg(short, long)]
    wordlist: Option<String>,

    /// Force install feroxbuster
    #[arg(long)]
    force_install: bool,
}

#[tokio::main]
async fn main() {
    std::env::set_var("RUST_BACKTRACE", "full");
    animation::run_intro_animation();
    let cli = Cli::parse();

    let config = if cli.scanner.is_some() {
        println!("Running at 5 RPS (default for non-interactive mode).");
        Config {
            request_delay: Duration::from_millis(200), // 5 RPS
        }
    } else {
        configure_rate_limit()
    };
    let rate_limiter = Arc::new(rate_limiter::RateLimiter::new(config.request_delay));

    let targets = if let Some(ref target_list) = cli.target_list {
        read_lines(target_list).unwrap_or_else(|_| panic!("Failed to read target list file"))
    } else {
        vec![match cli.target.as_ref() {
            Some(target) => target.clone(),
            None => match Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter the target website URL")
                .interact_text()
            {
                Ok(target) => target,
                Err(_) => {
                    eprintln!("Could not read target URL. Are you running in a non-interactive shell? Try specifying a target with the --target argument.");
                    return;
                }
            },
        }]
    };

    let concurrency = if cli.target_list.is_some() {
        let num: usize = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("How many websites would you like to run through at a time?")
            .interact_text()
            .unwrap_or(1);
        println!("{}", "[WARNING] Concurrent scans can multiply your RPS and may get your IP blacklisted. Proceed with caution.".yellow());
        num
    } else {
        1
    };

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = vec![];

    for target_url in targets {
        let mut url_with_scheme = target_url.clone();
        if !url_with_scheme.starts_with("http://") && !url_with_scheme.starts_with("https://") {
            url_with_scheme = format!("http://{}", url_with_scheme);
        }

        let cli = Arc::new(cli.clone());
        let rate_limiter = Arc::clone(&rate_limiter);
        let semaphore = Arc::clone(&semaphore);

        tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            run_scan(&cli, &rate_limiter, &url_with_scheme).await;
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
}

async fn run_scan(cli: &Cli, rate_limiter: &Arc<rate_limiter::RateLimiter>, target_url: &str) {
    let selection = match &cli.scanner {
        Some(scanner) if scanner.to_lowercase() == "xss" => 0,
        Some(scanner) if scanner.to_lowercase() == "dir" => 1,
        Some(scanner) if scanner.to_lowercase() == "file" => 2,
        Some(scanner) if scanner.to_lowercase() == "sql" => 3,
        Some(scanner) if scanner.to_lowercase() == "bypass" || scanner == "403" => 4,
        None => match Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an option")
            .items(&[
                "XSS",
                "Open Directory",
                "File Inclusion",
                "SQL Injection",
                "403/401 Bypass",
            ])
            .interact()
        {
            Ok(selection) => selection,
            Err(_) => {
                eprintln!("Could not read selection. Are you running in a non-interactive shell? Try specifying a scanner with the --scanner argument.");
                return;
            }
        },
        _ => {
            eprintln!("Invalid scanner type provided. Available options: xss, dir, file, sql, bypass/403");
            return;
        }
    };

    let m = MultiProgress::new();
    let sty = ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}",
    )
    .unwrap()
    .progress_chars("#>-");

    let url = match Url::parse(&target_url) {
        Ok(url) => url,
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            eprintln!("Error: Invalid URL. Please provide an absolute URL (e.g., http://example.com)");
            return;
        }
        Err(e) => {
            eprintln!("Error: Invalid URL: {}", e);
            return;
        }
    };

    let reporter = Arc::new(reporter::Reporter::new(url.clone()));

    if selection == 0 {
        let (found_urls, found_forms) = match crawl_target(url.clone(), &m, &sty, &rate_limiter).await {
            Ok((urls, forms)) => (urls, forms),
            Err(_) => return,
        };

        let scanner = xss::XssScanner::new(found_urls.clone(), found_forms.clone(), &reporter, Arc::clone(rate_limiter));
        let pb_scan = m.add(ProgressBar::new(
            (found_urls.len() * scanner.payloads_count()
                + found_forms.len() * scanner.payloads_count()) as u64,
        ));
        pb_scan.set_style(sty.clone());

        if let Err(e) = scanner.scan(&pb_scan).await {
            pb_scan.finish_with_message(format!("Scanning failed: {}", e));
            eprintln!("Error scanning for XSS: {}", e);
        } else {
            pb_scan.finish_with_message("Scanning complete");
        }
    } else if selection == 1 {
        if cli.force_install || !dependency_manager::is_feroxbuster_installed() {
            let confirm = if cli.force_install || cli.scanner.is_some() {
                0
            } else {
                Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Feroxbuster is not installed. Would you like to install it now?")
                    .items(&["Yes", "No"])
                    .interact()
                    .unwrap()
            };

            if confirm == 0 {
                let pb_install = m.add(ProgressBar::new_spinner());
                pb_install.set_style(sty.clone());
                pb_install.set_message("Installing feroxbuster...");
                if let Err(e) = dependency_manager::install_feroxbuster().await {
                    pb_install.finish_with_message(format!("Failed to install feroxbuster: {}", e));
                    return;
                }
                pb_install.finish_with_message("Feroxbuster installed successfully");
            } else {
                println!("Feroxbuster is required for the Open Directory Scanner to work.");
                return;
            }
        }

        let pb_dir = m.add(ProgressBar::new_spinner());
        pb_dir.set_style(sty.clone());
        let dir_scanner = dir_scanner::DirScanner::new(url.clone(), &pb_dir, cli.wordlist.clone(), &reporter);

        if let Err(e) = dir_scanner.scan().await {
            pb_dir.finish_with_message(format!("Directory scan failed: {}", e));
            eprintln!("Error scanning for directories: {}", e);
        } else {
            pb_dir.finish_with_message("Directory scan complete");
        }
    } else if selection == 2 {
        let (found_urls, found_forms) = match crawl_target(url.clone(), &m, &sty, &rate_limiter).await {
            Ok((urls, forms)) => (urls, forms),
            Err(_) => return,
        };

        let scanner = file_inclusion_scanner::FileInclusionScanner::new(
            found_urls.clone(),
            found_forms.clone(),
            &reporter,
            Arc::clone(rate_limiter),
        );
        let pb_scan = m.add(ProgressBar::new(
            (found_urls.len() * scanner.payloads_count()
                + found_forms.len() * scanner.payloads_count()) as u64,
        ));
        pb_scan.set_style(sty.clone());

        if let Err(e) = scanner.scan(&pb_scan).await {
            pb_scan.finish_with_message(format!("Scanning failed: {}", e));
            eprintln!("Error scanning for file inclusion: {}", e);
        } else {
            pb_scan.finish_with_message("Scanning complete");
        }
    } else if selection == 3 {
        let (found_urls, found_forms) = match crawl_target(url.clone(), &m, &sty, &rate_limiter).await {
            Ok((urls, forms)) => (urls, forms),
            Err(_) => return,
        };

        let scanner = sql_injection_scanner::SqlInjectionScanner::new(
            found_urls.clone(),
            found_forms.clone(),
            &reporter,
            Arc::clone(rate_limiter),
        );
        let pb_scan = m.add(ProgressBar::new(
            (found_urls.len() * scanner.payloads_count()
                + found_forms.len() * scanner.payloads_count()) as u64,
        ));
        pb_scan.set_style(sty.clone());

        if let Err(e) = scanner.scan(&pb_scan).await {
            pb_scan.finish_with_message(format!("Scanning failed: {}", e));
            eprintln!("Error scanning for SQL injection: {}", e);
        } else {
            pb_scan.finish_with_message("Scanning complete");
        }
    } else if selection == 4 {
        let pb_bypass = m.add(ProgressBar::new(100));
        pb_bypass.set_style(sty.clone());
        let bypass_scanner = bypass_403::BypassScanner::new(url.clone(), &pb_bypass, &reporter, Arc::clone(rate_limiter));

        if let Err(e) = bypass_scanner.scan().await {
            pb_bypass.finish_with_message(format!("403 bypass scan failed: {}", e));
            eprintln!("Error scanning for 403 bypasses: {}", e);
        } else {
            pb_bypass.finish_with_message("403 bypass scan complete");
        }
    }
}

fn read_lines<P>(filename: P) -> io::Result<Vec<String>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    io::BufReader::new(file).lines().collect()
}
