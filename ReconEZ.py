import os
import subprocess

# Helper function to run shell commands
def run_command(command):
    return subprocess.check_output(command, shell=True).decode('utf-8').splitlines()

# Step 1: Subdomain Enumeration
def enumerate_subdomains(domain):
    subdomains = set()
    subfinder_cmd = f"subfinder -d {domain} -silent"
    amass_cmd = f"amass enum -passive -d {domain} -silent"
    assetfinder_cmd = f"assetfinder --subs-only {domain}"

    # Combine results from multiple tools
    subdomains.update(run_command(subfinder_cmd))
    subdomains.update(run_command(amass_cmd))
    subdomains.update(run_command(assetfinder_cmd))

    return list(subdomains)

# Step 2: Categorize Subdomains Based on Status Code
def categorize_subdomains(subdomains):
    live_subdomains = []
    subdomain_file = 'subdomains.txt'
    
    # Save subdomains to file
    with open(subdomain_file, 'w') as f:
        f.write("\n".join(subdomains))

    httpx_cmd = f"cat {subdomain_file} | httpx -silent -status-code"
    result = run_command(httpx_cmd)

    # Categorize based on status code
    for line in result:
        subdomain, status_code = line.split(" ")
        if status_code == '200':
            live_subdomains.append(subdomain)
    
    return live_subdomains

# Step 3: Directory Fuzzing
def fuzz_directories(subdomains, wordlist):
    for subdomain in subdomains:
        ffuf_cmd = f"ffuf -w {wordlist} -u https://{subdomain}/FUZZ -mc 200"
        print(run_command(ffuf_cmd))

# Step 4: Fetch Wayback URLs
def fetch_wayback_urls(subdomains):
    wayback_urls = []
    for subdomain in subdomains:
        wayback_cmd = f"echo {subdomain} | waybackurls"
        wayback_urls.extend(run_command(wayback_cmd))
    
    return wayback_urls

# Step 5: Filter Active Endpoints (200 OK)
def filter_active_endpoints(urls):
    active_endpoints = []
    urls_file = 'urls.txt'

    with open(urls_file, 'w') as f:
        f.write("\n".join(urls))

    httpx_cmd = f"cat {urls_file} | httpx -silent -status-code 200"
    active_endpoints.extend(run_command(httpx_cmd))

    return active_endpoints

# Step 6: Filter Sensitive Extensions
def filter_sensitive_extensions(urls):
    sensitive_extensions = ['env', 'config', 'sql', 'bak']
    sensitive_files = []

    for ext in sensitive_extensions:
        grep_cmd = f"grep '\.{ext}$' urls.txt"
        sensitive_files.extend(run_command(grep_cmd))
    
    return sensitive_files

# Step 7: Analyze JavaScript Files for Sensitive Information
def analyze_js_files(subdomains):
    js_files = []
    keywords = ['password', 'token', 'apikey', 'secret']

    for subdomain in subdomains:
        js_grep_cmd = f"echo {subdomain} | grep '\.js$'"
        js_files.extend(run_command(js_grep_cmd))

    # Grep through JS files for sensitive keywords
    for js_file in js_files:
        for keyword in keywords:
            grep_cmd = f"curl -s {js_file} | grep -i {keyword}"
            print(run_command(grep_cmd))

# Main automation workflow
def main(domain):
    subdomains = enumerate_subdomains(domain)
    live_subdomains = categorize_subdomains(subdomains)
    
    # Fuzz directories on live subdomains
    fuzz_directories(live_subdomains, '/path/to/wordlist.txt')
    
    # Fetch wayback URLs and filter active endpoints
    wayback_urls = fetch_wayback_urls(live_subdomains)
    active_endpoints = filter_active_endpoints(wayback_urls)

    # Identify sensitive extensions
    sensitive_files = filter_sensitive_extensions(active_endpoints)

    # Analyze JS files for sensitive information
    analyze_js_files(live_subdomains)

# Run the script
if __name__ == "__main__":
    target_domain = "example.com"
    main(target_domain)

