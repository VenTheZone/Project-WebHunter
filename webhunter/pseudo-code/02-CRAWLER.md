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


STRUCTURE Crawler:
    DESCRIPTION: Crawls a target website to discover URLs and forms
    
    FIELDS:
        target_url: URL                    // Starting URL
        visited_urls: HashSet<URL>         // Already crawled URLs
        user_agents: Vector<String>        // Rotating user agents
        forms: Vector<Form>                // Discovered forms


FUNCTION Crawler::new(target_url):
    DESCRIPTION: Creates a new crawler instance
    
    INPUT:
        target_url: URL object
    
    OUTPUT:
        Crawler instance
    
    PROCESS:
        CREATE new crawler
        SET target_url = target_url
        INITIALIZE visited_urls as empty HashSet
        INITIALIZE user_agents with:
            - "Googlebot"
            - "Bingbot"
            - "Yahoo! Slurp"
            - "DuckDuckBot"
            - "Facebot"
            - "curl/7.68.0"
            - "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        INITIALIZE forms as empty Vector
        RETURN crawler


ASYNC FUNCTION Crawler::crawl(progress_bar):
    DESCRIPTION: Crawls the target website with depth-limited traversal
    
    INPUT:
        progress_bar: ProgressBar reference
    
    OUTPUT:
        Result containing (Vector<URL>, Vector<Form>) or Error
    
    ALGORITHM:
        SET max_depth = 2
        INITIALIZE urls_to_visit = [target_url]
        INITIALIZE found_urls as empty Vector
        
        FOR depth FROM 0 TO max_depth - 1:
            CREATE next_urls as empty HashSet
            COPY urls_to_visit to urls_at_current_depth
            CLEAR urls_to_visit
            
            FOR EACH url IN urls_at_current_depth:
                // Skip already visited URLs
                IF url is IN visited_urls:
                    CONTINUE to next URL
                
                // Update progress
                SET progress_bar message "Crawling: {url}"
                ADD url to visited_urls
                ADD url to found_urls
                
                // Send HTTP request with rotating user agent
                CREATE HTTP client
                SELECT user_agent = user_agents[depth % user_agents.length]
                
                TRY:
                    SEND GET request to url with user_agent header
                    STORE response

                    // Skip 404 responses
                    IF response.status == 404:
                        CONTINUE to next URL
                CATCH error:
                    CONTINUE to next URL
                
                INCREMENT progress_bar by 1
                
                // Parse HTML response
                TRY:
                    GET response body as text
                    PARSE body as HTML document

                    // Extract links (URLs to crawl)
                    SELECT all elements matching "a, img, link, script"

                    FOR EACH element IN selected_elements:
                        DETERMINE attribute to extract:
                            IF element is "a" OR "link":
                                GET "href" attribute
                            ELSE IF element is "img" OR "script":
                                GET "src" attribute
                            ELSE:
                                SKIP element

                        IF attribute exists:
                            TRY:
                                RESOLVE relative URL against current url
                                STORE as new_url

                                // Only follow same-domain HTTP(S) URLs
                                IF new_url.domain == target_url.domain
                                   AND (new_url.scheme == "http" OR new_url.scheme == "https"):
                                    REMOVE fragment from new_url

                                    IF new_url NOT IN visited_urls:
                                        ADD new_url to next_urls
                            CATCH URL parsing error:
                                SKIP this URL

                    // Extract forms
                    SELECT all form elements

                    FOR EACH form_element IN forms:
                        EXTRACT action = form_element.attribute("action") OR ""
                        EXTRACT method = form_element.attribute("method") OR "get"

                        INITIALIZE inputs as empty Vector
                        SELECT all input elements within form

                        FOR EACH input_element IN inputs:
                            EXTRACT name = input_element.attribute("name") OR ""

                            // Skip inputs without names
                            IF name is empty:
                                CONTINUE

                            EXTRACT value = input_element.attribute("value") OR ""

                            CREATE FormInput with name and value
                            ADD to inputs Vector

                        CREATE Form with action, method, inputs, and current url
                        ADD form to self.forms

                CATCH parsing error:
                    // Silently skip malformed HTML
                    PASS

                // Rate limiting
                SLEEP for 200 milliseconds
            
            // Prepare next depth level
            ADD all URLs from next_urls to urls_to_visit
        
        RETURN Ok((found_urls, self.forms))


HELPER STRUCTURE FormInput:
    FIELDS:
        name: String
        value: String


HELPER STRUCTURE Form:
    FIELDS:
        action: String      // Form action URL
        method: String      // HTTP method (GET/POST)
        inputs: Vector<FormInput>
        url: URL           // Page where form was found
```

## Algorithm Analysis

```pseudo
CRAWLING ALGORITHM:
    Type: Breadth-First Search (BFS) with depth limit

    Time Complexity: O(N * D)
        N = number of pages
        D = max depth (2)

    Space Complexity: O(N)
        N = total URLs discovered

    Rate Limiting:
        - 200ms delay between requests
        - ~5 requests per second
        - Polite crawling to avoid server overload

VISITED TRACKING:
    Data Structure: HashSet
    Purpose: Prevent duplicate crawls
    Lookup Time: O(1) average case

USER AGENT ROTATION:
    Strategy: Round-robin based on depth
    Purpose: Mimic different browsers/bots
    Count: 7 different user agents
```

## Edge Cases Handled

```pseudo
EDGE_CASES:
    1. 404 Not Found:
       - Skip and continue to next URL

    2. Relative URLs:
       - Resolved against current page URL

    3. Fragment identifiers (#):
       - Removed (same page, different anchor)

    4. Cross-domain links:
       - Ignored (only crawl target domain)

    5. Non-HTTP(S) schemes:
       - Ignored (e.g., mailto:, javascript:)

    6. Forms without inputs:
       - Still recorded but won't be tested

    7. Inputs without names:
       - Skipped (can't be submitted)

    8. Network errors:
       - Silently caught, continue crawling

    9. Malformed HTML:
       - Parser handles gracefully
```

## Data Flow

```pseudo
DATA_FLOW:
    Input: target_url
    ↓
    Initialize crawler with target_url
    ↓
    FOR each depth level (0 to max_depth):
        ↓
        FOR each URL at current depth:
            ↓
            Send HTTP request
            ↓
            Parse HTML response
            ↓
            Extract links → Add to next_urls
            ↓
            Extract forms → Add to forms list
            ↓
            Mark URL as visited
    ↓
    Output: (all_discovered_urls, all_discovered_forms)
```
