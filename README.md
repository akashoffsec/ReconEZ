# ReconEZ
ReconEZ is a automation tool used to perform the initial recon process in more easier.


# Automation Flow
Here’s the combined automation flow:

1. Subdomain Enumeration: Collect subdomains using Subfinder, Amass, and Assetfinder.
2. Categorization by HTTP Response: Filter subdomains by HTTP status using Httpx.
3. Fuzzing: Perform directory fuzzing on subdomains that respond with 200 OK or relevant status codes.
4. Wayback Machine URLs: Get historical URLs using Waybackurls or gau.
5. Active Endpoints Filtering: Filter active URLs based on the status code 200 OK.
6. Sensitive Extension Identification: Grep for sensitive file extensions (e.g., .env, .sql).
7. JavaScript File Analysis: Fetch and grep .js files for sensitive keywords.
