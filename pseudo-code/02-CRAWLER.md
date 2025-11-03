# Web Crawler Module - Pseudo-Code
## File: crawler.rs

```pseudo
IMPORT libraries:
    - reqwest (HTTP client)
    - scraper (HTML parsing)
    - url (URL manipulation)
    - tokio (async runtime)
    - indicatif (progress tracking)

IMPORT modules:
    - form (Form, FormInput structures)
    - rate_limiter (RateLimiter structure)

STRUCTURE Crawler:
    DESCRIPTION: Crawls a target website to discover URLs and forms
    
    FIELDS:
        target_url: URL
        visited_urls: HashSet<URL>
        user_agents: Vector<&'static str>
        forms: Vector<Form>
        rate_limiter: Arc<RateLimiter>

FUNCTION Crawler::new(target_url, rate_limiter):
    DESCRIPTION: Creates a new crawler instance
    
    INPUT:
        target_url: URL object
        rate_limiter: Arc<RateLimiter>
    
    OUTPUT:
        Crawler instance
    
    PROCESS:
        CREATE new crawler
        SET target_url = target_url
        SET rate_limiter = rate_limiter
        INITIALIZE visited_urls as empty HashSet
        INITIALIZE user_agents with a list of common user agents
        INITIALIZE forms as empty Vector
        RETURN crawler

ASYNC FUNCTION Crawler::crawl(progress_bar):
    DESCRIPTION: Crawls the target website with depth-limited traversal
    
    INPUT:
        progress_bar: ProgressBar reference
    
    OUTPUT:
        Result containing (Vector<URL>, Vector<Form>) or Error
    
    ALGORITHM:
        SET max_depth = 3
        INITIALIZE urls_to_visit = [target_url]
        INITIALIZE found_urls as empty Vector
        
        FOR depth FROM 0 TO max_depth - 1:
            CREATE next_urls as empty HashSet
            COPY urls_to_visit to urls_at_current_depth
            CLEAR urls_to_visit
            
            FOR EACH url IN urls_at_current_depth:
                IF url is IN visited_urls, CONTINUE
                
                SET progress_bar message "Crawling: {url}"
                ADD url to visited_urls
                ADD url to found_urls
                
                CREATE HTTP client
                SELECT user_agent from user_agents
                AWAIT rate_limiter.wait()
                
                TRY:
                    SEND GET request to url with user_agent header
                    IF response.status is 404, CONTINUE
                CATCH error, CONTINUE
                
                INCREMENT progress_bar by 1
                
                IF response body is Ok:
                    PARSE body as HTML document
                    EXTRACT links and add to next_urls
                    EXTRACT forms and add to self.forms
            
            ADD all URLs from next_urls to urls_to_visit
        
        RETURN Ok((found_urls, self.forms))

HELPER STRUCTURE FormInput:
    FIELDS:
        name: String
        value: String

HELPER STRUCTURE Form:
    FIELDS:
        action: String
        method: String
        inputs: Vector<FormInput>
        url: URL
```

## Algorithm Analysis

```pseudo
CRAWLING ALGORITHM:
    Type: Breadth-First Search (BFS) with depth limit
    Time Complexity: O(N * D) where N is pages and D is max_depth
    Space Complexity: O(N) for discovered URLs

RATE LIMITING:
    - Uses a RateLimiter to control request frequency.

VISITED TRACKING:
    Data Structure: HashSet for O(1) average case lookup.

USER AGENT ROTATION:
    Strategy: Rotates through a list of user agents.
```

## Edge Cases Handled

```pseudo
EDGE_CASES:
    1. 404 Not Found: Skips the URL.
    2. Relative URLs: Resolved against the current page URL.
    3. URL Fragments: Removed to avoid duplicate pages.
    4. Cross-domain links: Ignored.
    5. Non-HTTP(S) schemes: Ignored.
    6. Forms without inputs: Recorded but not tested.
    7. Inputs without names: Skipped.
    8. Network errors: Caught and crawling continues.
    9. Malformed HTML: Handled by the parser.
```

## Data Flow

```pseudo
DATA_FLOW:
    Input: target_url, rate_limiter
    ↓
    Initialize crawler
    ↓
    BFS traversal up to max_depth:
        - Send HTTP request (respecting rate limit)
        - Parse HTML
        - Extract links and forms
        - Add to respective data structures
    ↓
    Output: (all_discovered_urls, all_discovered_forms)
```