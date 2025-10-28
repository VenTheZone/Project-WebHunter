use crate::file_inclusion_scanner::FileInclusionVulnerability;
use crate::sql_injection_scanner::SqlInjectionVulnerability;
use crate::xss::Vulnerability;
use std::fs;
use std::io::Write;
use url::Url;
use chrono::Local;

pub struct Reporter;

impl Reporter {
    pub fn new() -> Self {
        Self
    }

    pub fn report(&self, vulnerabilities: &[Vulnerability], target_url: &Url) -> std::io::Result<()> {
        let domain = target_url.domain().unwrap_or("unknown_domain").replace(".", "_");
        fs::create_dir_all(&domain)?;

        let file_path = format!("{}/XSS-output.md", domain);
        let mut file = fs::File::create(file_path)?;

        writeln!(file, "# WebHunter XSS Scan Report for {}", target_url)?;
        writeln!(file, "**Scan completed on:** {}", Local::now())?;
        writeln!(file, "---")?;

        if vulnerabilities.is_empty() {
            writeln!(file, "## No XSS vulnerabilities found.")?;
        } else {
            for vuln in vulnerabilities {
                writeln!(file, "## Vulnerability Found:")?;
                writeln!(file, "- **URL:** {}", vuln.url)?;
                writeln!(file, "- **Type:** {}", vuln.vuln_type)?;
                writeln!(file, "- **Severity:** {}", vuln.severity)?;
                writeln!(file, "- **Parameter:** {}", vuln.parameter)?;
                writeln!(file, "- **Payload:** `{}`", vuln.payload)?;
                writeln!(file, "---")?;
            }
        }
        Ok(())
    }

    pub fn report_sql_injection(
        &self,
        vulnerabilities: &[SqlInjectionVulnerability],
        target_url: &Url,
    ) -> std::io::Result<()> {
        let domain = target_url.domain().unwrap_or("unknown_domain").replace(".", "_");
        fs::create_dir_all(&domain)?;

        let file_path = format!("{}/Sql-Injection-output.txt", domain);
        let mut file = fs::File::create(file_path)?;

        writeln!(file, "WebHunter SQL Injection Scan Report for {}", target_url)?;
        writeln!(file, "Scan completed on: {}", Local::now())?;
        writeln!(file, "--------------------------------------------------")?;

        if vulnerabilities.is_empty() {
            writeln!(file, "No SQL injection vulnerabilities found.")?;
        } else {
            for vuln in vulnerabilities {
                writeln!(file, "Vulnerability Found:")?;
                writeln!(file, "  URL: {}", vuln.url)?;
                writeln!(file, "  Type: {}", vuln.vuln_type)?;
                writeln!(file, "  Parameter: {}", vuln.parameter)?;
                writeln!(file, "  Payload: {}", vuln.payload)?;
                writeln!(file, "--------------------------------------------------")?;
            }
        }
        Ok(())
    }

    pub fn report_file_inclusion(
        &self,
        vulnerabilities: &[FileInclusionVulnerability],
        target_url: &Url,
    ) -> std::io::Result<()> {
        let domain = target_url.domain().unwrap_or("unknown_domain").replace(".", "_");
        fs::create_dir_all(&domain)?;

        let file_path = format!("{}/File-Inclusion-output.txt", domain);
        let mut file = fs::File::create(file_path)?;

        writeln!(file, "WebHunter File Inclusion Scan Report for {}", target_url)?;
        writeln!(file, "Scan completed on: {}", Local::now())?;
        writeln!(file, "--------------------------------------------------")?;

        if vulnerabilities.is_empty() {
            writeln!(file, "No file inclusion vulnerabilities found.")?;
        } else {
            for vuln in vulnerabilities {
                writeln!(file, "Vulnerability Found:")?;
                writeln!(file, "  URL: {}", vuln.url)?;
                writeln!(file, "  Type: {}", vuln.vuln_type)?;
                writeln!(file, "  Parameter: {}", vuln.parameter)?;
                writeln!(file, "  Payload: {}", vuln.payload)?;
                writeln!(file, "--------------------------------------------------")?;
            }
        }
        Ok(())
    }

    pub fn report_dirs(&self, found_dirs: &[(Url, u16, u64)], target_url: &Url, wordlist: &str) -> std::io::Result<()> {
        let domain = target_url.domain().unwrap_or("unknown_domain").replace(".", "_");
        fs::create_dir_all(&domain)?;

        let file_path = format!("{}/Open-Directories-output.md", domain);
        let mut file = fs::File::create(file_path)?;

        writeln!(file, "# WebHunter Open Directory Scan Report for {}", target_url)?;
        writeln!(file, "**Scan completed on:** {}", Local::now())?;
        writeln!(file, "---")?;

        if found_dirs.is_empty() {
            writeln!(file, "## No open directories found.")?;
        } else {
            writeln!(file, "## Summary")?;
            writeln!(file, "WebHunter discovered one or more open directories on the target server. This could lead to the exposure of sensitive information.")?;
            writeln!(file, "")?;
            writeln!(file, "## Scan Details")?;
            writeln!(file, "- **Tool Used:** feroxbuster")?;
            writeln!(file, "- **Command:** `feroxbuster -u {} -w {} --json --silent`", target_url, wordlist)?;
            writeln!(file, "")?;
            writeln!(file, "## Description")?;
            writeln!(file, "Open directories, also known as directory listing, is a feature that, when enabled, lists the contents of a directory when no index file is present. This can expose sensitive information to attackers, such as configuration files, source code, or other confidential data.")?;
            writeln!(file, "")?;
            writeln!(file, "## Impact")?;
            writeln!(file, "Exposure of sensitive data and information leakage that could aid further attacks.")?;
            writeln!(file, "")?;
            writeln!(file, "## Steps to Reproduce")?;
            writeln!(file, "The following URLs can be accessed with a web browser to view the directory contents:")?;
            writeln!(file, "")?;
            writeln!(file, "## Remediation")?;
            writeln!(file, "Disable directory listing on your web server. For example, on an Apache server, you can add `Options -Indexes` to your `.htaccess` file or server configuration.")?;
            writeln!(file, "---")?;
            writeln!(file, "## Findings")?;
            writeln!(file, "| URL | Status | Content-Length | Severity |")?;
            writeln!(file, "|---|---|---|---|")?;
            for (url, status, content_length) in found_dirs {
                writeln!(file, "| [{}]({}) | {} | {} bytes | Medium |", url, url, status, content_length)?;
            }
        }
        Ok(())
    }
}
