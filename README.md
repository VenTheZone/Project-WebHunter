# WebHunter

<p align="center">
  <img src="logo.png" alt="WebHunter Logo" width="400"/>
</p>

A fast, Rust-based web vulnerability scanner for finding OWASP Top 10 issues in web applications.

## Features

### Vulnerability Scanners

- **XSS** - Reflected, stored, and DOM-based XSS detection
- **SQL Injection** - Error-based, boolean-based, and time-based SQLi
- **CSRF** - Missing anti-CSRF token detection with auto-generated PoC exploits
- **File Inclusion** - LFI and RFI detection via pattern matching
- **Auth Bypass** - SQL injection login bypass and default credential testing
- **Access Control** - IDOR detection, forced browsing, HTTP method override testing
- **403/401 Bypass** - URL manipulation, header injection, method switching
- **CORS Misconfiguration** - Wildcard origins, null origin, credentials + wildcard
- **SSRF** - Server-side request forgery testing with OOB callback support
- **Exposed Files** - Source map detection and debug endpoint fuzzing
- **Open Directory** - Powered by feroxbuster

### Other Features

- Configurable rate limiting (RPS control)
- Bulk target scanning from file
- Concurrent scanning
- Markdown reports organized by vulnerability type
- 64+ passing tests

## Quick Start

```bash
# Interactive mode
cargo run

# Quick scan (no crawling)
cargo run -- --scanner cors --target https://example.com --no-crawl

# Specify scanner
cargo run -- --scanner sql --target https://example.com
```

## CLI Options

| Option | Description |
|--------|-------------|
| `--target` | Single target URL |
| `--target-list` | File with URLs (one per line) |
| `--scanner` | Scanner type (see below) |
| `--no-crawl` | Skip crawling, scan target URL directly |
| `--max-depth` | Maximum crawl depth (default: 2) |
| `--max-urls` | Maximum URLs to crawl (default: 50) |

## Available Scanners

| Scanner | Flag |
|---------|------|
| XSS | `xss` |
| SQL Injection | `sql` |
| CSRF | `csrf` |
| File Inclusion | `file` |
| Auth Bypass | `auth` |
| Access Control | `bac` |
| 403/401 Bypass | `bypass` |
| Directory | `dir` |
| CORS | `cors` |
| SSRF | `ssrf` |
| Exposed Files | `exposed` |

## Building

```bash
cargo build --release
./target/release/webhunter --scanner xss --target https://example.com
```

## Testing

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt -- --check
```

## Wordlists

Customize wordlists in `wordlists/`:

- `xss/payloads.txt` - XSS polyglots
- `sql_injection/` - Boolean, error, time-based payloads
- `ssrf/payloads.txt` - localhost, cloud metadata, internal IPs
- `exposed_files/` - Source maps and debug endpoints

## Reports

Reports go to directories named after targets (dots converted to underscores):

```
example_com_443/
├── XSS-output.md
├── SQL-Injection-output.md
└── ...
```

## Warning

Only scan targets you own or have permission to test. Unauthorized scanning is illegal.

## License

Apache-2.0
