# WebHunter - Project Overview Pseudo-Code

## High-Level Architecture

```
PROJECT: WebHunter
PURPOSE: Ethical hacking command-line tool for web vulnerability scanning
LANGUAGE: Rust
TYPE: Security Testing Tool

MAIN COMPONENTS:
├── Main Application (main.rs)
├── Crawler Module (crawler.rs)
├── Vulnerability Scanners:
│   ├── XSS Scanner (xss.rs)
│   ├── SQL Injection Scanner (sql_injection_scanner.rs)
│   ├── File Inclusion Scanner (file_inclusion_scanner.rs)
│   └── Directory Scanner (dir_scanner.rs)
├── Form Parser (form.rs)
├── Reporter (reporter.rs)
├── Dependency Manager (dependency_manager.rs)
└── Animation Module (animation.rs)
```

## Core Workflow

```pseudo
PROGRAM WebHunter:
    INPUT: target_url, scanner_type, optional_wordlist
    OUTPUT: vulnerability_report

    INITIALIZE:
        Display animated banner
        Parse command-line arguments or prompt user
        Validate target URL
        Set up progress tracking system

    SCANNER_SELECTION:
        IF scanner_type == "XSS":
            RUN xss_vulnerability_scan
        ELSE IF scanner_type == "Directory":
            CHECK feroxbuster installation
            RUN directory_brute_force_scan
        ELSE IF scanner_type == "File Inclusion":
            RUN file_inclusion_scan
        ELSE IF scanner_type == "SQL Injection":
            RUN sql_injection_scan

    GENERATE_REPORT:
        CREATE output directory based on target domain
        WRITE findings to markdown/text report
        DISPLAY summary to console

    EXIT
```

## Module Dependencies

```pseudo
DEPENDENCY_GRAPH:
    main.rs
    ├── Uses: clap (CLI parsing)
    ├── Uses: dialoguer (interactive prompts)
    ├── Uses: indicatif (progress bars)
    └── Imports all scanner modules

    crawler.rs
    ├── Depends on: reqwest (HTTP client)
    ├── Depends on: scraper (HTML parsing)
    └── Uses: form.rs (form data structures)

    Each Scanner Module:
    ├── Depends on: reqwest (HTTP requests)
    ├── Depends on: form.rs (form handling)
    ├── Uses: wordlist files (payloads)
    └── Returns: vulnerability list

    reporter.rs
    ├── Depends on: chrono (timestamps)
    └── Generates: markdown reports
```

## Data Flow

```pseudo
DATA_FLOW:
    1. User Input → CLI Parser → Validated Configuration
    2. Target URL → Crawler → (URLs + Forms)
    3. (URLs + Forms) + Payloads → Scanner → Vulnerabilities
    4. Vulnerabilities → Reporter → Report Files
    5. Progress Updates → Progress Bars → Console Display
```

## Key Features

```pseudo
FEATURES:
    - Multi-scanner architecture (XSS, SQLi, LFI/RFI, Directory)
    - Intelligent web crawling with depth control
    - Form detection and testing
    - Multiple user-agent rotation
    - Rate limiting and polite scanning
    - Progress visualization
    - Comprehensive reporting in markdown format
    - External tool integration (feroxbuster)
    - Automatic dependency management
```

## Security Considerations

```pseudo
ETHICAL_USAGE:
    - Tool designed for authorized security testing only
    - Implements rate limiting to prevent DoS
    - Respects HTTP error codes (404 handling)
    - Delays between requests (50-200ms)
    - No aggressive scanning by default
    - Clear vulnerability reporting for remediation
```
