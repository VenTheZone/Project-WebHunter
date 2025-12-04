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
    output_dir: Option<std::path::PathBuf>,
}

impl Reporter {
    pub fn new(target_url: Url) -> Self {
        Self {
            target_url,
            report_files: Mutex::new(HashMap::new()),
            output_dir: None,
        }
    }

    pub fn with_output_dir(mut self, path: std::path::PathBuf) -> Self {
        self.output_dir = Some(path);
        self
    }

    fn get_report_file(&self, file_name: &str) -> std::io::Result<File> {
        let mut files = self.report_files.lock().unwrap();
        if let Some(file) = files.get(file_name) {
            return file.try_clone();
        }

        let host = self.target_url.host_str().unwrap_or("unknown_host");
        let port = self.target_url.port_or_known_default().unwrap_or(80);
        let dir_name = format!("{}_{}", host.replace('.', "_"), port);

        let dir_path = if let Some(ref base) = self.output_dir {
            base.join(&dir_name)
        } else {
            std::path::PathBuf::from(&dir_name)
        };

        fs::create_dir_all(&dir_path)?;
        let file_path = dir_path.join(file_name);
        println!("Writing report to: {:?}", file_path);

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

    pub fn report_xss(&self, vuln: &crate::xss::Vulnerability) {
        let mut file = self.get_report_file("XSS-output.md").unwrap();

        writeln!(file, "## XSS Vulnerability Found:").unwrap();
        writeln!(
            file,
            "- **Proof of Concept:** [{}]({})",
            vuln.proof_of_concept, vuln.proof_of_concept
        )
        .unwrap();
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
    pub fn report_dom_xss(&self, vuln: &crate::dom_xss_scanner::DomXssVulnerability) {
        let mut file = self.get_report_file("DOM-XSS-output.md").unwrap();

        writeln!(file, "## DOM-based XSS Vulnerability Found:").unwrap();
        writeln!(file, "| URL | Source | Sink | Line | Severity |").unwrap();
        writeln!(file, "|---|---|---|---|---|").unwrap();
        writeln!(
            file,
            "| [{}]({}) | `{}` | `{}` | {} | {} |",
            vuln.url, vuln.url, vuln.source, vuln.sink, vuln.line_number, vuln.severity
        )
        .unwrap();

        writeln!(file, "\n### Vulnerable Code:").unwrap();
        writeln!(file, "```javascript\n{}\n```", vuln.code_snippet).unwrap();
        writeln!(file, "---").unwrap();
    }

    pub fn report_csrf(&self, vuln: &crate::csrf_scanner::CsrfVulnerability) {
        let mut file = self.get_report_file("CSRF-output.md").unwrap();

        writeln!(file, "## CSRF Vulnerability Found:").unwrap();
        writeln!(
            file,
            "| URL | Form Action | Method | Missing Protections | Severity |"
        )
        .unwrap();
        writeln!(file, "|---|---|---|---|---|").unwrap();
        writeln!(
            file,
            "| [{}]({}) | {} | {} | {} | {} |",
            vuln.url,
            vuln.url,
            vuln.form_action,
            vuln.method,
            vuln.missing_protections.join(", "),
            vuln.severity
        )
        .unwrap();

        writeln!(file, "\n### Proof of Concept:").unwrap();
        writeln!(file, "```html\n{}\n```", vuln.poc_html).unwrap();
        writeln!(file, "---").unwrap();
    }

    pub fn report_access_control(
        &self,
        vuln: &crate::access_control_scanner::AccessControlVulnerability,
    ) {
        if let Ok(mut file) = self.get_report_file("Access-Control-output.md") {
            let _ = writeln!(file, "## Access Control Vulnerability Found");
            let _ = writeln!(file, "- **URL:** {}", vuln.url);
            let _ = writeln!(file, "- **Type:** {}", vuln.vuln_type);
            let _ = writeln!(file, "- **Severity:** {}", vuln.severity);
            let _ = writeln!(file, "- **Payload:** `{}`", vuln.payload);
            let _ = writeln!(file, "- **Description:** {}", vuln.description);
            let _ = writeln!(file, "---");
        }
    }

    pub fn report_auth_bypass(&self, vuln: &crate::auth_bypass_scanner::AuthBypassVulnerability) {
        if let Ok(mut file) = self.get_report_file("auth_bypass_report.md") {
            let _ = writeln!(file, "## Authentication Bypass Found");
            let _ = writeln!(file, "- **URL:** {}", vuln.url);
            let _ = writeln!(file, "- **Form Action:** {}", vuln.form_action);
            let _ = writeln!(file, "- **Type:** {}", vuln.vuln_type);
            let _ = writeln!(file, "- **Payload:** `{}`", vuln.payload);
            let _ = writeln!(file, "- **Description:** {}", vuln.description);
            let _ = writeln!(file, "---");
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_reporter() -> (Reporter, TempDir) {
        let temp_dir = TempDir::new().unwrap();

        let url = Url::parse("https://example.com").unwrap();
        let reporter = Reporter::new(url).with_output_dir(temp_dir.path().to_path_buf());

        (reporter, temp_dir)
    }

    #[test]
    fn test_reporter_creation_basic() {
        let url = Url::parse("https://test.example.com").unwrap();
        let reporter = Reporter::new(url.clone());

        // Verify the target URL is stored
        assert_eq!(reporter.target_url, url);
    }

    #[test]
    fn test_report_xss() {
        let (reporter, temp_dir) = create_test_reporter();

        let vuln = crate::xss::Vulnerability {
            proof_of_concept: Url::parse("https://example.com/page?q=<script>alert(1)</script>")
                .unwrap(),
            parameter: "q".to_string(),
            payload: "<script>alert(1)</script>".to_string(),
            vuln_type: "Reflected XSS".to_string(),
            severity: "Medium".to_string(),
            method: "GET".to_string(),
            technique: "Basic".to_string(),
        };

        reporter.report_xss(&vuln);

        // Force flush by dropping reporter
        std::mem::drop(reporter);

        let report_path = temp_dir.path().join("example_com_443/XSS-output.md");
        assert!(
            report_path.exists(),
            "XSS report file should exist at {:?}",
            report_path
        );

        // Verify content
        let content = fs::read_to_string(report_path).unwrap();
        assert!(content.contains("XSS Vulnerability Found"));
        assert!(content.contains("<script>alert(1)</script>"));
        assert!(content.contains("Reflected"));
    }

    #[test]
    fn test_report_sql_injection() {
        let (reporter, temp_dir) = create_test_reporter();

        let vuln = crate::sql_injection_scanner::SqlInjectionVulnerability {
            url: Url::parse("https://example.com/page?id=1'").unwrap(),
            parameter: "id".to_string(),
            payload: "1'".to_string(),
            vuln_type: "Error-based".to_string(),
        };

        reporter.report_sql_injection(&vuln);

        // Force flush by dropping reporter
        std::mem::drop(reporter);

        let report_path = temp_dir
            .path()
            .join("example_com_443/Sql-Injection-output.md");
        assert!(
            report_path.exists(),
            "SQL injection report file should exist at {:?}",
            report_path
        );

        let content = fs::read_to_string(report_path).unwrap();
        assert!(content.contains("SQL Injection Vulnerability Found"));
        assert!(content.contains("Error-based"));
        assert!(content.contains("1'"));
    }

    #[test]
    fn test_report_file_inclusion() {
        let (reporter, temp_dir) = create_test_reporter();

        let vuln = crate::file_inclusion_scanner::FileInclusionVulnerability {
            url: Url::parse("https://example.com/page?file=../../../etc/passwd").unwrap(),
            parameter: "file".to_string(),
            payload: "../../../etc/passwd".to_string(),
            vuln_type: "LFI".to_string(),
        };

        reporter.report_file_inclusion(&vuln);

        // Force flush by dropping reporter
        std::mem::drop(reporter);

        let report_path = temp_dir
            .path()
            .join("example_com_443/File-Inclusion-output.txt");
        assert!(
            report_path.exists(),
            "File inclusion report file should exist at {:?}",
            report_path
        );

        let content = fs::read_to_string(report_path).unwrap();
        assert!(content.contains("Vulnerability Found"));
        assert!(content.contains("LFI"));
        assert!(content.contains("../../../etc/passwd"));
    }

    #[test]
    fn test_report_directory() {
        let (reporter, temp_dir) = create_test_reporter();

        let url = Url::parse("https://example.com/admin/").unwrap();
        reporter.report_directory(&url, 200, 1024);

        // Force flush by dropping reporter
        std::mem::drop(reporter);

        let report_path = temp_dir
            .path()
            .join("example_com_443/Open-Directories-output.md");
        assert!(
            report_path.exists(),
            "Directory report file should exist at {:?}",
            report_path
        );

        let content = fs::read_to_string(report_path).unwrap();
        assert!(content.contains("Open Directory Found"));
        assert!(content.contains("200"));
        assert!(content.contains("1024 bytes"));
    }
}
