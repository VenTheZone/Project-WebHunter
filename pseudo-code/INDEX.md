# WebHunter Pseudo-Code Index

Quick reference guide for navigating the pseudo-code documentation.

## Document List

| # | File | Module | Lines | Description |
|---|------|--------|-------|-------------|
| 0 | [00-PROJECT-OVERVIEW.md](00-PROJECT-OVERVIEW.md) | Overview | ~150 | High-level architecture, workflow, features |
| 1 | [01-MAIN.md](01-MAIN.md) | main.rs | ~400 | Application entry point, CLI, scanner orchestration |
| 2 | [02-CRAWLER.md](02-CRAWLER.md) | crawler.rs | ~300 | Web crawling, URL discovery, form extraction |
| 3 | [03-XSS-SCANNER.md](03-XSS-SCANNER.md) | xss.rs | ~450 | XSS vulnerability detection (reflected & stored) |
| 4 | [04-SQL-INJECTION-SCANNER.md](04-SQL-INJECTION-SCANNER.md) | sql_injection_scanner.rs | ~550 | SQL injection testing (error/boolean/time-based) |
| 5 | [05-FILE-INCLUSION-SCANNER.md](05-FILE-INCLUSION-SCANNER.md) | file_inclusion_scanner.rs | ~500 | LFI/RFI vulnerability detection |
| 6 | [06-DIRECTORY-SCANNER.md](06-DIRECTORY-SCANNER.md) | dir_scanner.rs | ~350 | Directory brute-forcing with feroxbuster |
| 7 | [07-REPORTER.md](07-REPORTER.md) | reporter.rs | ~500 | Report generation in multiple formats |
| 8 | [08-SUPPORTING-MODULES.md](08-SUPPORTING-MODULES.md) | form.rs, etc. | ~400 | Data structures, utilities, animation |
| 9 | [09-403-BYPASS-SCANNER.md](09-403-BYPASS-SCANNER.md) | bypass_403.rs | ~300 | 403/401 bypass detection and snapshotting |

**Total Lines of Pseudo-Code**: ~3,900 lines

## Quick Navigation by Topic

### Architecture & Design
- [Project Overview](00-PROJECT-OVERVIEW.md#high-level-architecture)
- [Module Dependencies](00-PROJECT-OVERVIEW.md#module-dependencies)
- [Data Flow](00-PROJECT-OVERVIEW.md#data-flow)
- [Design Patterns](08-SUPPORTING-MODULES.md#design-patterns)

### User Interface
- [CLI Parsing](01-MAIN.md#structure-commandlineinterface)
- [Interactive Prompts](01-MAIN.md#get-scanner-selection)
- [Progress Tracking](01-MAIN.md#initialize-progress-tracking)
- [Startup Animation](08-SUPPORTING-MODULES.md#file-animationrs)

### Web Crawling
- [Crawler Algorithm](02-CRAWLER.md#async-function-crawlercrawl)
- [URL Discovery](02-CRAWLER.md#extract-links-urls-to-crawl)
- [Form Extraction](02-CRAWLER.md#extract-forms)
- [BFS Algorithm](02-CRAWLER.md#algorithm-analysis)

### Vulnerability Scanning

#### XSS Detection
- [XSS Scanner Overview](03-XSS-SCANNER.md#structure-xssscanner)
- [URL Parameter Testing](03-XSS-SCANNER.md#async-function-xssscannerscanurlsprogress_bar)
- [Form Testing](03-XSS-SCANNER.md#async-function-xssscannerScan_forms)
- [Detection Logic](03-XSS-SCANNER.md#function-xssscannerisvulnerable)

#### SQL Injection
- [SQL Scanner Overview](04-SQL-INJECTION-SCANNER.md#structure-sqlinjectionscanner)
- [Error-Based Detection](04-SQL-INJECTION-SCANNER.md#async-function-sqlinjectionscannertesterrorbased)
- [Boolean-Based Detection](04-SQL-INJECTION-SCANNER.md#async-function-sqlinjectionscannertestbooleanbased)
- [Time-Based Detection](04-SQL-INJECTION-SCANNER.md#async-function-sqlinjectionscannertesttimebased)

#### File Inclusion
- [File Inclusion Scanner](05-FILE-INCLUSION-SCANNER.md#structure-fileinclusionscanner)
- [LFI Detection](05-FILE-INCLUSION-SCANNER.md#local-file-inclusion-lfi)
- [RFI Detection](05-FILE-INCLUSION-SCANNER.md#remote-file-inclusion-rfi)
- [Evidence Patterns](05-FILE-INCLUSION-SCANNER.md#evidence_detection)

#### Directory Scanning
- [Directory Scanner](06-DIRECTORY-SCANNER.md#structure-dirscanner)
- [Feroxbuster Integration](06-DIRECTORY-SCANNER.md#feroxbuster-integration)
- [JSON Parsing](06-DIRECTORY-SCANNER.md#json_output_format)
- [Wordlist Strategy](06-DIRECTORY-SCANNER.md#wordlist-strategy)

### Reporting
- [Report Generation](07-REPORTER.md#structure-reporter)
- [Markdown Format](07-REPORTER.md#markdown_format)
- [Severity Classification](07-REPORTER.md#severity_levels)
- [Output Organization](07-REPORTER.md#output_organization)

### Algorithms & Complexity
- [Crawler BFS](02-CRAWLER.md#algorithm-analysis)
- [XSS Testing Strategy](03-XSS-SCANNER.md#testing-strategy)
- [SQL Injection Complexity](04-SQL-INJECTION-SCANNER.md#complexity_analysis)
- [Rate Limiting](00-PROJECT-OVERVIEW.md#key-features)

### Security & Ethics
- [Ethical Usage](00-PROJECT-OVERVIEW.md#ethical_usage)
- [Rate Limiting](02-CRAWLER.md#rate-limiting)
- [Polite Scanning](06-DIRECTORY-SCANNER.md#polite_scanning)
- [Responsible Testing](README.md#responsible-testing)

### Implementation Details
- [Data Structures](08-SUPPORTING-MODULES.md#file-formrs)
- [Dependency Management](08-SUPPORTING-MODULES.md#file-dependency_managerrs)
- [Error Handling](01-MAIN.md#error-handling)
- [Async Operations](02-CRAWLER.md#async-function-crawlercrawl)

## Key Concepts by Module

### Main Application (main.rs)
- CLI argument parsing with clap
- Interactive user prompts with dialoguer
- Progress tracking with indicatif
- Scanner orchestration
- Error handling and reporting

### Crawler (crawler.rs)
- Breadth-first search (BFS) traversal
- Depth-limited crawling (max depth: 2)
- User-agent rotation (7 different agents)
- Rate limiting (200ms delay)
- HTML parsing with scraper
- Form and URL extraction

### XSS Scanner (xss.rs)
- Payload loading from wordlists
- URL parameter injection
- Form input injection
- Reflected XSS detection
- Stored XSS detection
- HTML attribute checking

### SQL Injection Scanner (sql_injection_scanner.rs)
- Three detection methods:
  1. Error-based (SQL error messages)
  2. Boolean-based (response comparison)
  3. Time-based (response delay measurement)
- Multiple database support
- Payload pair testing for boolean-based

### File Inclusion Scanner (file_inclusion_scanner.rs)
- Local File Inclusion (LFI) testing
- Remote File Inclusion (RFI) testing
- Path traversal payloads
- Evidence pattern matching
- Encoding bypass attempts

### Directory Scanner (dir_scanner.rs)
- External tool integration (feroxbuster)
- JSON output parsing
- Wordlist management
- Status code filtering
- Concurrent directory discovery

### Reporter (reporter.rs)
- Markdown report generation
- Multiple vulnerability types
- Timestamp and metadata
- Severity classification
- Remediation guidance

### Supporting Modules
- Form data structures
- Dependency checking and installation
- Terminal animations and UI
- Helper utilities

## Complexity Summary

| Module | Time Complexity | Space Complexity | Notes |
|--------|----------------|------------------|-------|
| Crawler | O(N × D) | O(N) | N=pages, D=depth(2) |
| XSS Scanner | O(U × P × M) | O(V) | U=URLs, P=payloads, M=params |
| SQL Scanner | O(U × P × M) | O(V) | Similar to XSS |
| File Inclusion | O(U × P × M) | O(V) | Similar to XSS |
| Directory Scanner | O(W) | O(R) | W=wordlist size, R=results |

Legend:
- N = Number of pages
- D = Crawl depth
- U = URLs/Forms to test
- P = Payloads per scanner
- M = Parameters per URL/Form
- V = Vulnerabilities found
- W = Wordlist entries
- R = Discovered directories

## Feature Matrix

| Feature | XSS | SQL | File Inc. | Directory |
|---------|-----|-----|-----------|-----------|
| URL Parameter Testing | ✓ | ✓ | ✓ | N/A |
| Form Testing | ✓ | ✓ | ✓ | N/A |
| Payload Wordlists | ✓ | ✓ | ✓ | ✓ |
| Rate Limiting | ✓ | ✓ | ✓ | ✓* |
| Progress Tracking | ✓ | ✓ | ✓ | ✓ |
| Markdown Reports | ✓ | ✓ | - | ✓ |
| Text Reports | - | - | ✓ | - |
| Severity Classification | ✓ | ✓ | ✓ | ✓ |
| Multiple Detection Methods | ✓ | ✓ | ✓ | N/A |

*Handled by feroxbuster

## Reading Paths

### Beginner Path
1. Start with [README.md](README.md)
2. Read [00-PROJECT-OVERVIEW.md](00-PROJECT-OVERVIEW.md)
3. Skim [01-MAIN.md](01-MAIN.md) for overall flow
4. Pick one scanner module based on interest
5. Explore [08-SUPPORTING-MODULES.md](08-SUPPORTING-MODULES.md)

### Developer Path
1. [00-PROJECT-OVERVIEW.md](00-PROJECT-OVERVIEW.md) - Architecture
2. [01-MAIN.md](01-MAIN.md) - Entry point
3. [02-CRAWLER.md](02-CRAWLER.md) - Async and web scraping
4. [08-SUPPORTING-MODULES.md](08-SUPPORTING-MODULES.md) - Utilities
5. [07-REPORTER.md](07-REPORTER.md) - File I/O
6. Individual scanner modules as needed

### Security Researcher Path
1. [00-PROJECT-OVERVIEW.md](00-PROJECT-OVERVIEW.md) - Understanding scope
2. [03-XSS-SCANNER.md](03-XSS-SCANNER.md) - XSS methodology
3. [04-SQL-INJECTION-SCANNER.md](04-SQL-INJECTION-SCANNER.md) - SQLi techniques
4. [05-FILE-INCLUSION-SCANNER.md](05-FILE-INCLUSION-SCANNER.md) - File inclusion
5. [06-DIRECTORY-SCANNER.md](06-DIRECTORY-SCANNER.md) - Information gathering

### Algorithm Analyst Path
1. [02-CRAWLER.md](02-CRAWLER.md#algorithm-analysis) - BFS algorithm
2. [03-XSS-SCANNER.md](03-XSS-SCANNER.md#testing-strategy) - Testing strategy
3. [04-SQL-INJECTION-SCANNER.md](04-SQL-INJECTION-SCANNER.md#complexity_analysis) - Complexity analysis
4. Study edge cases in each scanner module

## Statistics

- **Total Pseudo-Code Files**: 9 (including README and INDEX)
- **Core Modules Documented**: 8
- **Vulnerability Types Covered**: 4 (XSS, SQLi, LFI/RFI, Open Directories)
- **Algorithms Documented**: 10+
- **Data Structures Defined**: 15+
- **Functions/Methods Documented**: 50+

## Updates and Maintenance

This pseudo-code documentation should be updated when:
- New scanner modules are added
- Detection algorithms are modified
- New features are implemented
- Architecture changes occur
- Bug fixes affect logic flow


---

**Quick Tips:**
- Use Ctrl+F to search for specific functions or concepts
- Follow links between documents for related topics
- Check the actual source code for implementation details
- Refer to README.md for conventions and guidelines
