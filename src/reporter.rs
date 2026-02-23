use crate::bypass_403::BypassBypass;
use crate::file_inclusion_scanner::FileInclusionVulnerability;
use crate::sql_injection_scanner::SqlInjectionVulnerability;
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

    #[allow(dead_code)] // Reserved for future custom output directory feature
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

    // Helper to get severity badge with color
    fn get_severity_badge(&self, severity: &str) -> String {
        match severity.to_lowercase().as_str() {
            "critical" => "🔴 **CRITICAL**".to_string(),
            "high" => "🟠 **HIGH**".to_string(),
            "medium" => "🟡 **MEDIUM**".to_string(),
            "low" => "🟢 **LOW**".to_string(),
            _ => format!("**{}**", severity.to_uppercase()),
        }
    }

    pub fn report_xss(&self, vuln: &crate::xss::Vulnerability) {
        if let Ok(mut file) = self.get_report_file("XSS-output.md") {
            let severity_badge = self.get_severity_badge(&vuln.severity);
            let _ = writeln!(file, "## 🎯 XSS Vulnerability Detected\n");
            let _ = writeln!(file, "| Field | Value |");
            let _ = writeln!(file, "|-------|-------|");
            let _ = writeln!(file, "| **Severity** | {} |", severity_badge);
            let _ = writeln!(file, "| **Type** | {} |", vuln.vuln_type);
            let _ = writeln!(file, "| **Method** | {} |", vuln.method);
            let _ = writeln!(
                file,
                "| **URL** | [{}]({}) |",
                vuln.proof_of_concept, vuln.proof_of_concept
            );
            let _ = writeln!(file, "| **Parameter** | `{}` |", vuln.parameter);
            let _ = writeln!(file, "| **Technique** | {} |", vuln.technique);
            let _ = writeln!(
                file,
                "\n### 💉 Payload\n```javascript\n{}\n```",
                vuln.payload
            );
            let _ = writeln!(file, "\n### 🛡️ Remediation\n- Implement proper input validation and output encoding\n- Use Content Security Policy (CSP) headers\n- Employ context-aware escaping");
            let _ = writeln!(file, "\n---\n");
        }
    }

    pub fn report_sql_injection(&self, vuln: &SqlInjectionVulnerability) {
        if let Ok(mut file) = self.get_report_file("SQL-Injection-output.md") {
            let _ = writeln!(file, "## 🎯 SQL Injection Vulnerability Detected\n");
            let _ = writeln!(file, "| Field | Value |");
            let _ = writeln!(file, "|-------|-------|");
            let _ = writeln!(file, "| **Severity** | 🔴 **CRITICAL** |");
            let _ = writeln!(file, "| **Type** | {} |", vuln.vuln_type);
            let _ = writeln!(file, "| **URL** | [{}]({}) |", vuln.url, vuln.url);
            let _ = writeln!(file, "| **Parameter** | `{}` |", vuln.parameter);
            let _ = writeln!(file, "\n### 💉 Payload\n```sql\n{}\n```", vuln.payload);
            let _ = writeln!(file, "\n### 🛡️ Remediation\n- Use parameterized queries (prepared statements)\n- Implement proper input validation\n- Apply principle of least privilege to database accounts\n- Use ORMs with built-in protection");
            let _ = writeln!(file, "\n---\n");
        }
    }

    pub fn report_file_inclusion(&self, vuln: &FileInclusionVulnerability) {
        if let Ok(mut file) = self.get_report_file("File-Inclusion-output.md") {
            let severity = if vuln.vuln_type == "RFI" {
                "CRITICAL"
            } else {
                "HIGH"
            };
            let severity_badge = self.get_severity_badge(severity);
            let _ = writeln!(file, "## 🎯 File Inclusion Vulnerability Detected\n");
            let _ = writeln!(file, "| Field | Value |");
            let _ = writeln!(file, "|-------|-------|");
            let _ = writeln!(file, "| **Severity** | {} |", severity_badge);
            let _ = writeln!(file, "| **Type** | {} |", vuln.vuln_type);
            let _ = writeln!(file, "| **URL** | [{}]({}) |", vuln.url, vuln.url);
            let _ = writeln!(file, "| **Parameter** | `{}` |", vuln.parameter);
            let _ = writeln!(file, "\n### 💉 Payload\n```\n{}\n```", vuln.payload);
            let _ = writeln!(file, "\n### 🛡️ Remediation\n- Never use user input directly in file paths\n- Implement a whitelist of allowed files\n- Use `basename()` to strip directory paths\n- Disable `allow_url_fopen` and `allow_url_include` in PHP");
            let _ = writeln!(file, "\n---\n");
        }
    }

    pub fn report_403_bypass(&self, bypass: &BypassBypass) {
        if let Ok(mut file) = self.get_report_file("403-Bypass-output.md") {
            let severity_badge = self.get_severity_badge(&bypass.severity);
            let _ = writeln!(file, "## 🎯 403/401 Bypass Detected\n");
            let _ = writeln!(file, "| Field | Value |");
            let _ = writeln!(file, "|-------|-------|");
            let _ = writeln!(file, "| **Severity** | {} |", severity_badge);
            let _ = writeln!(file, "| **Technique** | {} |", bypass.technique);
            let _ = writeln!(file, "| **Method** | {} |", bypass.method);
            let _ = writeln!(
                file,
                "| **Original URL** | [{}]({}) |",
                bypass.url, bypass.url
            );
            let _ = writeln!(
                file,
                "| **Bypass URL** | [{}]({}) |",
                bypass.bypass_url, bypass.bypass_url
            );
            let _ = writeln!(file, "| **Headers** | `{}` |", bypass.headers);
            let _ = writeln!(file, "\n### 🛡️ Remediation\n- Implement consistent access control checks\n- Validate authorization on both frontend and backend\n- Use centralized authentication/authorization framework\n- Test with various HTTP methods and headers");
            let _ = writeln!(file, "\n---\n");
        }
    }

    pub fn report_directory(&self, url: &Url, status: u16, content_length: u64) {
        if let Ok(mut file) = self.get_report_file("Open-Directories-output.md") {
            let _ = writeln!(file, "## 🎯 Open Directory Detected\n");
            let _ = writeln!(file, "| Field | Value |");
            let _ = writeln!(file, "|-------|-------|");
            let _ = writeln!(file, "| **Severity** | 🟡 **MEDIUM** |");
            let _ = writeln!(file, "| **URL** | [{}]({}) |", url, url);
            let _ = writeln!(file, "| **Status Code** | {} |", status);
            let _ = writeln!(file, "| **Content Length** | {} bytes |", content_length);
            let _ = writeln!(file, "\n### 🛡️ Remediation\n- Disable directory listing in web server configuration\n- Add index.html/index.php files to all directories\n- Configure proper access controls\n- Review exposed files for sensitive data");
            let _ = writeln!(file, "\n---\n");
        }
    }

    pub fn report_dom_xss(&self, vuln: &crate::dom_xss_scanner::DomXssVulnerability) {
        if let Ok(mut file) = self.get_report_file("DOM-XSS-output.md") {
            let severity_badge = self.get_severity_badge(&vuln.severity);
            let _ = writeln!(file, "## 🎯 DOM-Based XSS Vulnerability Detected\n");
            let _ = writeln!(file, "| Field | Value |");
            let _ = writeln!(file, "|-------|-------|");
            let _ = writeln!(file, "| **Severity** | {} |", severity_badge);
            let _ = writeln!(file, "| **URL** | [{}]({}) |", vuln.url, vuln.url);
            let _ = writeln!(file, "| **Source** | `{}` |", vuln.source);
            let _ = writeln!(file, "| **Sink** | `{}` |", vuln.sink);
            let _ = writeln!(file, "| **Line Number** | {} |", vuln.line_number);
            let _ = writeln!(
                file,
                "\n### 💉 Vulnerable Code\n```javascript\n{}\n```",
                vuln.code_snippet
            );
            let _ = writeln!(file, "\n### 🛡️ Remediation\n- Avoid using dangerous sinks (eval, innerHTML, document.write)\n- Use safe APIs like textContent or setAttribute\n- Implement Content Security Policy (CSP)\n- Sanitize data from untrusted sources before DOM manipulation");
            let _ = writeln!(file, "\n---\n");
        }
    }

    pub fn report_csrf(&self, vuln: &crate::csrf_scanner::CsrfVulnerability) {
        if let Ok(mut file) = self.get_report_file("CSRF-output.md") {
            let severity_badge = self.get_severity_badge(&vuln.severity);
            let _ = writeln!(file, "## 🎯 CSRF Vulnerability Detected\n");
            let _ = writeln!(file, "| Field | Value |");
            let _ = writeln!(file, "|-------|-------|");
            let _ = writeln!(file, "| **Severity** | {} |", severity_badge);
            let _ = writeln!(file, "| **URL** | [{}]({}) |", vuln.url, vuln.url);
            let _ = writeln!(file, "| **Form Action** | {} |", vuln.form_action);
            let _ = writeln!(file, "| **Method** | {} |", vuln.method);
            let _ = writeln!(
                file,
                "| **Missing Protections** | {} |",
                vuln.missing_protections.join(", ")
            );
            let _ = writeln!(
                file,
                "\n### 💉 Proof of Concept\n```html\n{}\n```",
                vuln.poc_html
            );
            let _ = writeln!(file, "\n### 🛡️ Remediation\n- Implement anti-CSRF tokens (synchronizer token pattern)\n- Use SameSite cookie attribute\n- Validate Origin/Referer headers\n- Require re-authentication for sensitive actions");
            let _ = writeln!(file, "\n---\n");
        }
    }

    pub fn report_access_control(
        &self,
        vuln: &crate::access_control_scanner::AccessControlVulnerability,
    ) {
        if let Ok(mut file) = self.get_report_file("Access-Control-output.md") {
            let severity_badge = self.get_severity_badge(&vuln.severity);
            let _ = writeln!(file, "## 🎯 Access Control Vulnerability Detected\n");
            let _ = writeln!(file, "| Field | Value |");
            let _ = writeln!(file, "|-------|-------|");
            let _ = writeln!(file, "| **Severity** | {} |", severity_badge);
            let _ = writeln!(file, "| **Type** | {} |", vuln.vuln_type);
            let _ = writeln!(file, "| **URL** | [{}]({}) |", vuln.url, vuln.url);
            let _ = writeln!(file, "| **Description** | {} |", vuln.description);
            let _ = writeln!(file, "\n### 💉 Payload\n```\n{}\n```", vuln.payload);
            let _ = writeln!(file, "\n### 🛡️ Remediation\n- Implement robust authorization checks for all resources\n- Use indirect object references (map user IDs to internal IDs)\n- Enforce role-based access control (RBAC)\n- Deny access by default, explicitly grant only when needed");
            let _ = writeln!(file, "\n---\n");
        }
    }

    pub fn report_auth_bypass(&self, vuln: &crate::auth_bypass_scanner::AuthBypassVulnerability) {
        if let Ok(mut file) = self.get_report_file("Authentication-Bypass-output.md") {
            let _ = writeln!(file, "## 🎯 Authentication Bypass Detected\n");
            let _ = writeln!(file, "| Field | Value |");
            let _ = writeln!(file, "|-------|-------|");
            let _ = writeln!(file, "| **Severity** | 🔴 **CRITICAL** |");
            let _ = writeln!(file, "| **Type** | {} |", vuln.vuln_type);
            let _ = writeln!(file, "| **URL** | [{}]({}) |", vuln.url, vuln.url);
            let _ = writeln!(file, "| **Form Action** | {} |", vuln.form_action);
            let _ = writeln!(file, "| **Description** | {} |", vuln.description);
            let _ = writeln!(file, "\n### 💉 Payload\n```\n{}\n```", vuln.payload);
            let _ = writeln!(file, "\n### 🛡️ Remediation\n- Use parameterized queries to prevent SQL injection in auth\n- Remove or change default credentials immediately\n- Implement account lockout after failed attempts\n- Use strong password policies and MFA");
            let _ = writeln!(file, "\n---\n");
        }
    }

    pub fn report_blind_xss(&self, vuln: &crate::blind_xss_scanner::BlindXssVulnerability) {
        if let Ok(mut file) = self.get_report_file("Blind-XSS-output.md") {
            let _ = writeln!(file, "## 🎯 Blind XSS Vulnerability Detected\n");
            let _ = writeln!(file, "| Field | Value |");
            let _ = writeln!(file, "|-------|-------|");
            let _ = writeln!(file, "| **Severity** | 🔴 **CRITICAL** |");
            let _ = writeln!(file, "| **URL** | [{}]({}) |", vuln.url, vuln.url);
            let _ = writeln!(file, "| **Parameter** | `{}` |", vuln.parameter);
            let _ = writeln!(file, "| **Payload ID** | {} |", vuln.payload_id);
            let _ = writeln!(file, "| **Callback Time** | {} |", vuln.callback_time);
            let _ = writeln!(file, "\n### 📡 Detection Method\nOut-of-band callback received, indicating stored XSS executed in a different context (admin panel, support dashboard, etc.)");
            let _ = writeln!(file, "\n### 🛡️ Remediation\n- Implement proper output encoding in ALL contexts\n- Use Content Security Policy (CSP)\n- Sanitize user input before storage\n- Validate and encode data when rendering in admin panels");
            let _ = writeln!(file, "\n---\n");
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
        assert!(content.contains("🎯 XSS Vulnerability Detected"));
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
            .join("example_com_443/SQL-Injection-output.md");
        assert!(
            report_path.exists(),
            "SQL injection report file should exist at {:?}",
            report_path
        );

        let content = fs::read_to_string(report_path).unwrap();
        assert!(content.contains("🎯 SQL Injection Vulnerability Detected"));
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
            .join("example_com_443/File-Inclusion-output.md");
        assert!(
            report_path.exists(),
            "File inclusion report file should exist at {:?}",
            report_path
        );

        let content = fs::read_to_string(report_path).unwrap();
        assert!(content.contains("🎯 File Inclusion Vulnerability Detected"));
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
        assert!(content.contains("🎯 Open Directory Detected"));
        assert!(content.contains("200"));
        assert!(content.contains("1024 bytes"));
    }
}
