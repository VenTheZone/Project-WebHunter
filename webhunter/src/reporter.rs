use crate::bypass_403::BypassBypass;
use crate::file_inclusion_scanner::FileInclusionVulnerability;
use crate::sql_injection_scanner::SqlInjectionVulnerability;
use crate::xss;
use chrono::Local;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use url::Url;

pub struct Reporter {
    target_url: Url,
    report_files: Mutex<HashMap<String, File>>,
}

impl Reporter {
    pub fn new(target_url: Url) -> Self {
        Self {
            target_url,
            report_files: Mutex::new(HashMap::new()),
        }
    }

    fn get_report_file(&self, file_name: &str) -> std::io::Result<File> {
        let mut files = self.report_files.lock().unwrap();
        if let Some(file) = files.get(file_name) {
            return Ok(file.try_clone()?);
        }

        let domain = self
            .target_url
            .domain()
            .unwrap_or("unknown_domain")
            .replace(".", "_");
        fs::create_dir_all(&domain)?;
        let file_path = format!("{}/{}", domain, file_name);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;

        writeln!(file, "# WebHunter Scan Report for {}", self.target_url)?;
        writeln!(file, "**Scan started on:** {}", Local::now())?;
        writeln!(file, "---")?;

        files.insert(file_name.to_string(), file.try_clone()?);
        Ok(file)
    }

    pub fn report_xss(&self, vuln: &xss::Vulnerability) {
        let mut file = self.get_report_file("XSS-output.md").unwrap();
        writeln!(file, "## XSS Vulnerability Found:").unwrap();
        writeln!(file, "- **Proof of Concept:** [{}]({})", vuln.proof_of_concept, vuln.proof_of_concept).unwrap();
        writeln!(file, "- **Method:** {}", vuln.method).unwrap();
        writeln!(file, "- **Type:** {}", vuln.vuln_type).unwrap();
        writeln!(file, "- **Severity:** {}", vuln.severity).unwrap();
        writeln!(file, "- **Parameter:** {}", vuln.parameter).unwrap();
        writeln!(file, "- **Payload:** `{}`", vuln.payload).unwrap();
        writeln!(file, "- **Technique:** {}", vuln.technique).unwrap();
        writeln!(file, "---").unwrap();
    }

    pub fn report_sql_injection(&self, vuln: &SqlInjectionVulnerability) {
        let mut file = self.get_report_file("Sql-Injection-output.md").unwrap();
        writeln!(file, "## SQL Injection Vulnerability Found:").unwrap();
        writeln!(file, "| URL | Parameter | Type | Payload | Severity |").unwrap();
        writeln!(file, "|---|---|---|---|---|").unwrap();
        writeln!(
            file,
            "| [{}]({}) | {} | {} | `{}` | High |",
            vuln.url, vuln.url, vuln.parameter, vuln.vuln_type, vuln.payload
        )
        .unwrap();
        writeln!(file, "---").unwrap();
    }

    pub fn report_file_inclusion(&self, vuln: &FileInclusionVulnerability) {
        let mut file = self.get_report_file("File-Inclusion-output.txt").unwrap();
        writeln!(file, "Vulnerability Found:").unwrap();
        writeln!(file, "  URL: {}", vuln.url).unwrap();
        writeln!(file, "  Type: {}", vuln.vuln_type).unwrap();
        writeln!(file, "  Parameter: {}", vuln.parameter).unwrap();
        writeln!(file, "  Payload: {}", vuln.payload).unwrap();
        writeln!(file, "--------------------------------------------------").unwrap();
    }

    pub fn report_403_bypass(&self, bypass: &BypassBypass) {
        // MD report
        let mut md_file = self.get_report_file("403-Bypass-output.md").unwrap();
        writeln!(md_file, "## 403 Bypass Found:").unwrap();
        writeln!(
            md_file,
            "| Original URL | Bypass URL | Method | Technique | Headers | Severity |"
        )
        .unwrap();
        writeln!(md_file, "|---|---|---|---|---|---|").unwrap();
        writeln!(
            md_file,
            "| [{}]({}) | [{}]({}) | {} | {} | `{}` | {} |",
            bypass.url,
            bypass.url,
            bypass.bypass_url,
            bypass.bypass_url,
            bypass.method,
            bypass.technique,
            bypass.headers,
            bypass.severity
        )
        .unwrap();
        writeln!(md_file, "---").unwrap();

        // TXT report
        let mut txt_file = self.get_report_file("403-Bypass-output.txt").unwrap();
        writeln!(
            txt_file,
            "Bypassed: {} with method {} and technique {}",
            bypass.bypass_url, bypass.method, bypass.technique
        )
        .unwrap();
    }

    pub fn report_directory(&self, url: &Url, status: u16, content_length: u64) {
        let mut file = self.get_report_file("Open-Directories-output.md").unwrap();
        writeln!(file, "## Open Directory Found:").unwrap();
        writeln!(file, "| URL | Status | Content-Length | Severity |").unwrap();
        writeln!(file, "|---|---|---|---|").unwrap();
        writeln!(
            file,
            "| [{}]({}) | {} | {} bytes | Medium |",
            url, url, status, content_length
        )
        .unwrap();
        writeln!(file, "---").unwrap();
    }
}
