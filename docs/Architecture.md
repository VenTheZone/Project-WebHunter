# WebHunter Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      WebHunter CLI                          │
│                  (Rust + Tokio + Clap)                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   Input Processing                          │
│  ┌──────────────┐    ┌──────────────┐    ┌─────────────┐  │
│  │  CLI Args    │    │  Target URL  │    │ File Input │  │
│  │  --scanner   │    │  Validation  │    │ (--list)   │  │
│  │  --no-crawl  │    │              │    │             │  │
│  └──────────────┘    └──────────────┘    └─────────────┘  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Rate Limiter                            │
│              (Tokio Semaphore + Config)                   │
└─────────────────────┬───────────────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
┌─────────────────────┐   ┌─────────────────────┐
│   Interactive UI    │   │  Non-Interactive    │
│   (Dialoguer)       │   │  (Direct Execution) │
└─────────┬───────────┘   └─────────┬───────────┘
          │                         │
          └───────────┬─────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   Scanner Pipeline                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
    ┌─────────┐ ┌─────────┐ ┌──────────┐
    │ Crawler │ │ Directory│ │  Direct   │
    │         │ │ Scanner  │ │  Target   │
    └────┬────┘ └────┬────┘ └─────┬────┘
         │           │            │
         ▼           ▼            ▼
    ┌────────────────────────────────────────┐
    │         Scanner Modules                │
    └────────────────────────────────────────┘
```

## Scanner Architecture

### Crawler-Based Scanners

```mermaid
flowchart TD
    A[Start] --> B[Crawler Module]
    B --> C[Extract URLs & Forms]
    C --> D{Scanner Type}
    
    D -->|XSS| E[XssScanner]
    D -->|SQLi| F[SqlInjectionScanner]
    D -->|CSRF| G[CsrfScanner]
    D -->|File| H[FileInclusionScanner]
    D -->|Auth| I[AuthBypassScanner]
    D -->|BAC| J[AccessControlScanner]
    D -->|CORS| K[CorsScanner]
    D -->|SSRF| L[SsrfScanner]
    D -->|Exposed| M[ExposedFilesScanner]
    
    E --> N[Load Payloads]
    F --> N
    G --> N
    H --> N
    I --> N
    J --> N
    K --> N
    L --> N
    M --> N
    
    N --> O[Inject Payloads]
    O --> P[Send HTTP Request]
    P --> Q[Rate Limit Wait]
    Q --> R{Response Analysis}
    
    R -->|Vulnerable| S[Record Finding]
    R -->|Clean| T{More Payloads?}
    T -->|Yes| O
    T -->|No| U[Report Results]
    
    S --> U
```

### Non-Crawler Scanners

```mermaid
flowchart LR
    A[Target URL] --> B[Direct Scan]
    
    B --> C[403 Bypass Scanner]
    B --> D[Directory Scanner]
    B --> E[No-Crawl Mode]
    
    C --> F[Path Wordlist]
    D --> G[Feroxbuster]
    E --> H[Single URL Test]
    
    F --> I[Results]
    G --> I
    H --> I
    
    I --> J[Reporter]
```

## Core Modules

### 1. Crawler (`crawler.rs`)

```mermaid
flowchart TD
    A[Start URL] --> B[Queue: Vec<Url>]
    B --> C{Pop URL}
    C -->|Empty| D[Done]
    C -->|Has URL| E[Fetch Page]
    
    E --> F[Parse HTML]
    F --> G[Extract Links]
    F --> H[Extract Forms]
    
    G --> I[Filter Same Domain]
    I --> J{Depth < MaxDepth?}
    J -->|Yes| K[Add to Queue]
    J -->|No| B
    
    H --> L[Store Forms]
    L --> B
    
    K --> B
```

### 2. Rate Limiter (`rate_limiter.rs`)

```
┌────────────────────────────────────┐
│         Rate Limiter              │
├────────────────────────────────────┤
│  Config:                          │
│  - requests_per_second: u32        │
│  - max_concurrent: usize          │
├────────────────────────────────────┤
│  Mechanism:                       │
│  - Tokio Semaphore                │
│  - Token Bucket Algorithm          │
│  - Per-request delay              │
└────────────────────────────────────┘
```

### 3. Scanners

#### XSS Scanner

```
Input: URLs + Forms
    │
    ▼
┌─────────────────────────────────┐
│ Payload Categories:              │
│ - Event Handlers (onerror,      │
│   onload, onmouseover...)       │
│ - Script Contexts (script,      │
│   svg, div...)                   │
│ - Polyglots                      │
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│ Detection:                       │
│ - Reflection analysis             │
│ - HTML parsing                   │
│ - DOM analysis                   │
└─────────────────────────────────┘
```

#### SSRF Scanner

```
Input: URLs with Parameters
    │
    ▼
┌─────────────────────────────────┐
│ Payload Types:                   │
│ - Localhost (127.0.0.1,         │
│   localhost, 0.0.0.0, ::1)       │
│ - Cloud Metadata (169.254.169.254)│
│ - Internal IPs (10.x.x.x,       │
│   192.168.x.x)                  │
│ - Protocols (file://, gopher://) │
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│ Detection:                       │
│ - Internal content in response   │
│ - Cloud metadata detection      │
│ - OOB callbacks                 │
└─────────────────────────────────┘
```

#### CORS Scanner

```
Input: Discovered URLs
    │
    ▼
┌─────────────────────────────────┐
│ Test Origins:                   │
│ - https://evil.com              │
│ - null                          │
│ - https://target.com.evil.com   │
│ - http://192.168.1.1           │
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│ Analyze Headers:                │
│ - Access-Control-Allow-Origin   │
│ - Access-Control-Allow-Creds    │
│ - Access-Control-Allow-Methods  │
│ - Access-Control-Allow-Headers  │
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│ Findings:                       │
│ - Critical: * + true creds      │
│ - High: null origin             │
│ - High: arbitrary origin         │
│ - Medium: permissive origin     │
└─────────────────────────────────┘
```

### 4. Reporter (`reporter.rs`)

```
┌─────────────────────────────────────┐
│            Reporter                 │
├─────────────────────────────────────┤
│ Outputs:                            │
│ - XSS-output.md                    │
│ - SQL-Injection-output.md           │
│ - CSRF-output.md + HTML PoCs        │
│ - CORS-Misconfiguration-output.md   │
│ - SSRF-output.md                    │
│ - Exposed-Files-output.md           │
├─────────────────────────────────────┤
│ Format:                             │
│ - Severity badge (🔴🟠🟡)           │
│ - Finding details table              │
│ - Description + PoC                │
│ - Remediation steps                │
└─────────────────────────────────────┘
```

## Data Flow

### Standard Scan Flow

```mermaid
sequenceDiagram
    participant CLI
    participant Crawler
    participant Scanner
    participant Target
    participant Reporter

    CLI->>Crawler: Start crawl
    Crawler->>Target: GET /
    Target-->>Crawler: HTML response
    Crawler->>Crawler: Extract URLs/Forms
    Crawler-->>CLI: discovered_urls[]

    CLI->>Scanner: Init with URLs
    Scanner->>Scanner: Load payloads
    Scanner->>Target: POST /search?q=<payload>
    Target-->>Scanner: Response
    Scanner->>Scanner: Analyze response

    alt Vulnerable
        Scanner->>Reporter: report_vulnerability()
        Reporter->>Reporter: Append to .md file
    end

    Scanner-->>CLI: Scan complete
    CLI->>CLI: Display summary
```

### No-Crawl Mode Flow

```mermaid
sequenceDiagram
    participant CLI
    participant Scanner
    participant Target

    CLI->>Scanner: Init with target_url only
    Scanner->>Target: Send test requests
    Target-->>Scanner: Response
    Scanner->>Scanner: Analyze headers/content
    
    alt Vulnerable
        Scanner->>Reporter: report_vulnerability()
    end
    
    Scanner-->>CLI: Results
```

## Wordlist Structure

```
wordlists/
├── access_control/
│   └── sensitive_paths.txt    # /admin, /config, /api/admin
├── auth_bypass/
│   ├── default_creds.txt       # admin:admin, root:toor
│   └── sqli_login_bypass.txt   # ' OR '1'='1
├── bypass_403/
│   ├── header_payloads.txt    # X-Original-URL, X-Rewrite-URL
│   ├── methods.txt            # PUT, DELETE, PATCH
│   └── url_payloads.txt       # /%2e/, /..;/ 
├── cors/
│   └── test_origins.txt       # Origins to test
├── exposed_files/
│   ├── debug_endpoints.txt    # /debug, /env, /config
│   └── source_maps.txt        # .map file paths
├── file_inclusion/
│   ├── lfi_payloads.txt      # ../../../etc/passwd
│   └── rfi_payloads.txt      # http://evil.com/shell
├── sql_injection/
│   ├── boolean_payloads.txt   # AND 1=1
│   ├── error_payloads.txt     # AND EXTRACTVALUE
│   └── time_payloads.txt     # AND SLEEP(5)
├── ssrf/
│   └── payloads.txt           # localhost, cloud IPs
└── xss/
    └── payloads.txt           # Polyglot XSS
```

## Error Handling

```mermaid
flowchart TD
    A[Request] --> B{Network Error?}
    B -->|Yes| C{Timeout?}
    B -->|No| D{Status Code?}
    
    C -->|Yes| E[Log + Continue]
    C -->|No| F[Retry once]
    
    D -->|4xx| G[Skip URL]
    D -->|5xx| H[Log + Continue]
    D -->|200| I[Analyze]
    
    F --> A
    E --> J{Next Payload?}
    I --> J
    
    J -->|Yes| A
    J -->|No| K[Next URL]
    K --> L{Done?}
    L -->|No| A
    L -->|Yes| M[Report]
```

## Performance Considerations

- **Async I/O**: All HTTP requests use Tokio async runtime
- **Rate Limiting**: Configurable RPS with semaphore-based throttling
- **Parallelism**: Multiple targets scanned concurrently (configurable)
- **Memory**: Efficient URL deduping with HashSet
- **Crawl Limits**: Configurable max_depth and max_urls prevent runaway crawls
