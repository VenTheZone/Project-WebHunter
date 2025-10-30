use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Input, Select};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use url::Url;

mod crawler;
mod dir_scanner;
mod form;
mod reporter;
mod xss;
mod dependency_manager;
mod file_inclusion_scanner;
mod sql_injection_scanner;
mod animation;

async fn crawl_target(
    url: Url,
    m: &MultiProgress,
    sty: &ProgressStyle,
) -> Result<(Vec<Url>, Vec<form::Form>), reqwest::Error> {
    let mut crawler = crawler::Crawler::new(url.clone());
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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The target website URL to scan
    #[arg(short, long)]
    target: Option<String>,

    /// The type of scanner to use
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
    animation::run_animation();
    let cli = Cli::parse();

    let target_url = match cli.target {
        Some(target) => target,
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
    };

    let selection = match cli.scanner {
        Some(scanner) if scanner.to_lowercase() == "xss" => 0,
        Some(scanner) if scanner.to_lowercase() == "dir" => 1,
        Some(scanner) if scanner.to_lowercase() == "file" => 2,
        Some(scanner) if scanner.to_lowercase() == "sql" => 3,
        None => match Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an option")
            .items(&[
                "XSS",
                "Open Directory",
                "File Inclusion",
                "SQL Injection",
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
            eprintln!("Invalid scanner type provided.");
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

    if selection == 0 {
        let (found_urls, found_forms) = match crawl_target(url.clone(), &m, &sty).await {
            Ok((urls, forms)) => (urls, forms),
            Err(_) => return,
        };

        let scanner = xss::XssScanner::new(found_urls.clone(), found_forms.clone());
        let pb_scan = m.add(ProgressBar::new(
            (found_urls.len() * scanner.payloads_count()
                + found_forms.len() * scanner.payloads_count()) as u64,
        ));
        pb_scan.set_style(sty.clone());

        match scanner.scan(&pb_scan).await {
            Ok(vulnerabilities) => {
                pb_scan.finish_with_message("Scanning complete");
                if vulnerabilities.is_empty() {
                    println!("No XSS vulnerabilities found.");
                } else {
                    println!("Found {} XSS vulnerabilities:", vulnerabilities.len());
                    let reporter = reporter::Reporter::new();
                    if let Err(e) = reporter.report(&vulnerabilities, &url) {
                        eprintln!("Error writing report: {}", e);
                    } else {
                        println!(
                            "Report saved to {}/XSS-output.md",
                            url.domain().unwrap_or("").replace(".", "_")
                        );
                    }
                }
            }
            Err(e) => {
                pb_scan.finish_with_message(format!("Scanning failed: {}", e));
                eprintln!("Error scanning for XSS: {}", e);
            }
        }
    } else if selection == 1 {
        if cli.force_install || !dependency_manager::is_feroxbuster_installed() {
            let confirm = if cli.force_install {
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
        let dir_scanner = dir_scanner::DirScanner::new(url.clone(), &pb_dir, cli.wordlist.clone());

        match dir_scanner.scan().await {
            Ok(found_dirs) => {
                pb_dir.finish_with_message("Directory scan complete");
                if found_dirs.is_empty() {
                    println!("No open directories found.");
                } else {
                    println!("Found {} open directories:", found_dirs.len());
                    let reporter = reporter::Reporter::new();
                    let wordlist = cli.wordlist.clone().unwrap_or("default_wordlist.txt".to_string());
                    if let Err(e) = reporter.report_dirs(&found_dirs, &url, &wordlist) {
                        eprintln!("Error writing report: {}", e);
                    } else {
                        println!(
                            "Report saved to {}/Open-Directories-output.md",
                            url.domain().unwrap_or("").replace(".", "_")
                        );
                    }
                }
            }
            Err(e) => {
                pb_dir.finish_with_message(format!("Directory scan failed: {}", e));
                eprintln!("Error scanning for directories: {}", e);
            }
        }
    } else if selection == 2 {
        let (found_urls, found_forms) = match crawl_target(url.clone(), &m, &sty).await {
            Ok((urls, forms)) => (urls, forms),
            Err(_) => return,
        };

        let scanner = file_inclusion_scanner::FileInclusionScanner::new(
            found_urls.clone(),
            found_forms.clone(),
        );
        let pb_scan = m.add(ProgressBar::new(
            (found_urls.len() * scanner.payloads_count()
                + found_forms.len() * scanner.payloads_count()) as u64,
        ));
        pb_scan.set_style(sty.clone());

        match scanner.scan(&pb_scan).await {
            Ok(vulnerabilities) => {
                pb_scan.finish_with_message("Scanning complete");
                if vulnerabilities.is_empty() {
                    println!("No file inclusion vulnerabilities found.");
                } else {
                    println!(
                        "Found {} file inclusion vulnerabilities:",
                        vulnerabilities.len()
                    );
                    let reporter = reporter::Reporter::new();
                    if let Err(e) = reporter.report_file_inclusion(&vulnerabilities, &url) {
                        eprintln!("Error writing report: {}", e);
                    } else {
                        println!(
                            "Report saved to {}/File-Inclusion-output.txt",
                            url.domain().unwrap_or("").replace(".", "_")
                        );
                    }
                }
            }
            Err(e) => {
                pb_scan.finish_with_message(format!("Scanning failed: {}", e));
                eprintln!("Error scanning for file inclusion: {}", e);
            }
        }
    } else if selection == 3 {
        let (found_urls, found_forms) = match crawl_target(url.clone(), &m, &sty).await {
            Ok((urls, forms)) => (urls, forms),
            Err(_) => return,
        };

        let scanner = sql_injection_scanner::SqlInjectionScanner::new(
            found_urls.clone(),
            found_forms.clone(),
        );
        let pb_scan = m.add(ProgressBar::new(
            (found_urls.len() * scanner.payloads_count()
                + found_forms.len() * scanner.payloads_count()) as u64,
        ));
        pb_scan.set_style(sty.clone());

        match scanner.scan(&pb_scan).await {
            Ok(vulnerabilities) => {
                pb_scan.finish_with_message("Scanning complete");
                if vulnerabilities.is_empty() {
                    println!("No SQL injection vulnerabilities found.");
                } else {
                    println!(
                        "Found {} SQL injection vulnerabilities:",
                        vulnerabilities.len()
                    );
                    let reporter = reporter::Reporter::new();
                    if let Err(e) = reporter.report_sql_injection(&vulnerabilities, &url) {
                        eprintln!("Error writing report: {}", e);
                    } else {
                        println!(
                            "Report saved to {}/Sql-Injection-output.txt",
                            url.domain().unwrap_or("").replace(".", "_")
                        );
                    }
                }
            }
            Err(e) => {
                pb_scan.finish_with_message(format!("Scanning failed: {}", e));
                eprintln!("Error scanning for SQL injection: {}", e);
            }
        }
    }
}
