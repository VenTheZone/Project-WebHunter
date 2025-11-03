# Reporter Module - Pseudo-Code
## File: reporter.rs

```pseudo
IMPORT libraries:
    - std::fs (file system operations)
    - std::io (I/O operations)
    - std::sync::Mutex (for thread-safe file handling)
    - url (URL manipulation)
    - chrono (date/time handling)

IMPORT modules:
    - xss (Vulnerability structure)
    - sql_injection_scanner (SqlInjectionVulnerability)
    - file_inclusion_scanner (FileInclusionVulnerability)
    - bypass_403 (BypassBypass structure)

STRUCTURE Reporter:
    FIELDS:
        target_url: Url
        report_files: Mutex<HashMap<String, File>>

FUNCTION Reporter::new(target_url):
    DESCRIPTION: Creates a new reporter instance.
    PROCESS:
        INITIALIZE and return Reporter instance with target_url and an empty file map.

FUNCTION Reporter::get_report_file(file_name) -> Result<File, Error>:
    DESCRIPTION: Gets a handle to a report file, creating it if it doesn't exist.
    PROCESS:
        LOCK the report_files map.
        IF file handle exists in map, CLONE and RETURN it.
        CREATE directory based on target domain.
        CREATE and open the report file.
        WRITE a header to the new file.
        INSERT the new file handle into the map.
        RETURN the cloned file handle.

FUNCTION Reporter::report_xss(vuln):
    DESCRIPTION: Appends an XSS vulnerability to the XSS report.
    PROCESS:
        GET handle to "XSS-output.md".
        WRITE vulnerability details in Markdown format.

FUNCTION Reporter::report_sql_injection(vuln):
    DESCRIPTION: Appends a SQL injection vulnerability to the SQL injection report.
    PROCESS:
        GET handle to "Sql-Injection-output.md".
        WRITE vulnerability details in a Markdown table.

FUNCTION Reporter::report_file_inclusion(vuln):
    DESCRIPTION: Appends a file inclusion vulnerability to the file inclusion report.
    PROCESS:
        GET handle to "File-Inclusion-output.txt".
        WRITE vulnerability details in plain text format.

FUNCTION Reporter::report_403_bypass(bypass):
    DESCRIPTION: Appends a 403 bypass finding to the report.
    PROCESS:
        GET handle to "403-Bypass-output.md" and "403-Bypass-output.txt".
        WRITE details to both files in their respective formats.

FUNCTION Reporter::report_directory(url, status, content_length):
    DESCRIPTION: Appends an open directory finding to the directory report.
    PROCESS:
        GET handle to "Open-Directories-output.md".
        WRITE directory details in a Markdown table.
```

## Report Formats

```pseudo
MARKDOWN_FORMAT:
    - Used for XSS, SQL Injection, 403 Bypass, and Open Directories reports.
    - Features clickable URLs and tables for structured data.

TEXT_FORMAT:
    - Used for File Inclusion and 403 Bypass reports.
    - Simple, plain text format.
```

## Directory Structure

```pseudo
OUTPUT_ORGANIZATION:
    - A directory is created based on the target's domain name (e.g., `example_com`).
    - All report files for that target are placed within this directory.
```