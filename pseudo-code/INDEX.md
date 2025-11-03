# WebHunter Pseudo-Code Index

Quick reference guide for navigating the pseudo-code documentation.

## Document List

| # | File | Module | Description |
|---|------|--------|-------------|
| 0 | [00-PROJECT-OVERVIEW.md](00-PROJECT-OVERVIEW.md) | Overview | High-level architecture, workflow, features |
| 1 | [01-MAIN.md](01-MAIN.md) | main.rs | Application entry point, CLI, scanner orchestration |
| 2 | [02-CRAWLER.md](02-CRAWLER.md) | crawler.rs | Web crawling, URL discovery, form extraction |
| 3 | [03-XSS-SCANNER.md](03-XSS-SCANNER.md) | xss.rs | XSS vulnerability detection |
| 4 | [04-SQL-INJECTION-SCANNER.md](04-SQL-INJECTION-SCANNER.md) | sql_injection_scanner.rs | SQL injection testing (error/boolean/time-based) |
| 5 | [05-FILE-INCLUSION-SCANNER.md](05-FILE-INCLUSION-SCANNER.md) | file_inclusion_scanner.rs | LFI/RFI vulnerability detection |
| 6 | [06-DIRECTORY-SCANNER.md](06-DIRECTORY-SCANNER.md) | dir_scanner.rs | Directory brute-forcing with feroxbuster |
| 7 | [07-REPORTER.md](07-REPORTER.md) | reporter.rs | Report generation in multiple formats |
| 8 | [08-SUPPORTING-MODULES.md](08-SUPPORTING-MODULES.md) | form.rs, etc. | Data structures, utilities, animation |
| 9 | [09-403-BYPASS-SCANNER.md](09-403-BYPASS-SCANNER.md) | bypass_403.rs | 403/401 bypass detection and snapshotting |

## Quick Navigation by Topic

### Vulnerability Scanning

- [XSS Detection](03-XSS-SCANNER.md)
- [SQL Injection](04-SQL-INJECTION-SCANNER.md)
- [File Inclusion](05-FILE-INCLUSION-SCANNER.md)
- [Directory Scanning](06-DIRECTORY-SCANNER.md)
- [403/401 Bypass](09-403-BYPASS-SCANNER.md)

## Key Concepts by Module

- **XSS Scanner:** Payload loading, URL and form injection, reflected XSS detection.
- **SQL Injection Scanner:** Error-based, boolean-based, and time-based detection.
- **File Inclusion Scanner:** LFI and RFI testing with evidence pattern matching.
- **Directory Scanner:** External tool integration (feroxbuster) and JSON parsing.
- **403/401 Bypass Scanner:** URL, method, and header-based bypass techniques with snapshotting.

## Feature Matrix

| Feature | XSS | SQL | File Inc. | Directory | 403 Bypass |
|---|---|---|---|---|---|
| URL Parameter Testing | ✓ | ✓ | ✓ | N/A | ✓ |
| Form Testing | ✓ | ✓ | ✓ | N/A | N/A |
| Payload Wordlists | ✓ | ✓ | ✓ | ✓ | ✓ |
| Rate Limiting | ✓ | ✓ | ✓ | ✓ | ✓ |
| Progress Tracking | ✓ | ✓ | ✓ | ✓ | ✓ |
| Reporting | ✓ | ✓ | ✓ | ✓ | ✓ |

## Statistics

- **Total Pseudo-Code Files**: 10 (excluding README, SUMMARY, and INDEX)
- **Core Modules Documented**: 9
- **Vulnerability Types Covered**: 5 (XSS, SQLi, LFI/RFI, Open Directories, 403/401 Bypass)