#!/bin/bash
# ================================================
# Advanced GitHub Recon Script
# Author: The Cybersecurity Professor (Enhanced by AI)
# Version: 3.1
# Purpose: Automates GitHub reconnaissance for bug bounty hunting.
# Features: Command-line args, modular functions, dorking, optional full clones,
#           secrets detection (Gitleaks, TruffleHog), JS endpoint extraction,
#           subdomain enumeration (code + subfinder), live host probing (httpx),
#           URL discovery (gau), screenshotting (gowitness), port scanning (naabu),
#           filesystem scanning (trivy fs), vuln scanning (Nuclei), basic config file,
#           rate limit checks, optional cleanup, JSON+MD summary reports, spinners.
# ================================================

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Script Information ---
SCRIPT_NAME=$(basename "$0")
SCRIPT_VERSION="3.1"

# --- Default Settings ---
DEFAULT_OUT_DIR_PREFIX="./github-recon-"
DEFAULT_CONFIG_FILE="recon.conf" # Simple key=value config file
GITHUB_DORKS=(
    '"api_key"' '"apikey"' '"secret_key"' '"secretkey"' '"password"'
    '"passwd"' '"credentials"' '"access_token"' '"accesstoken"'
    '"client_secret"' '"clientsecret"' 'filename:.env' 'filename:.npmrc'
    'filename:.dockercfg' 'filename:config.js' 'filename:settings.py'
    'extension:pem' 'extension:ppk' 'extension:key' 'extension:json api'
    'extension:yaml' 'internal' 'staging' 'deploy' 'backup' 'database'
    'admin' 'jenkins' 'BEGIN RSA PRIVATE KEY' 'BEGIN PGP PRIVATE KEY BLOCK'
    'BEGIN OPENSSH PRIVATE KEY'
)
# Nuclei templates - adjust as needed
NUCLEI_TEMPLATES="technologies,cves,misconfiguration,vulnerabilities"
NUCLEI_EXCLUSIONS="info,misc" # Tags to exclude

# --- Global Variables ---
declare -a TARGET_DOMAINS=() # Array to hold specified domains
GH_TARGET=""
OUT_DIR=""
LOG_FILE=""
SUMMARY_REPORT_MD_FILE=""
SUMMARY_REPORT_JSON_FILE=""
CONFIG_FILE="$DEFAULT_CONFIG_FILE"
GITHUB_TOKEN_VAR="" # Store token from env or config

FULL_CLONE=false
CLEANUP_REPOS=false
# Flags to control execution flow
RUN_DORKING=true
RUN_CLONING=true
RUN_SECRETS_SCAN=true
RUN_TRIVY_FS=true # New flag for Trivy FS scan
RUN_ENDPOINT_EXTRACTION=true
RUN_SUBDOMAIN_EXTRACTION=true
RUN_SUBFINDER=true
RUN_HTTPX=true
RUN_NAABU=true # New flag for Naabu port scan
RUN_GAU=true
RUN_GOWITNESS=true
RUN_NUCLEI=true

# --- Utility Functions ---

# Log messages with timestamp and level
log_msg() {
    local level="$1"
    local color="$2"
    local message="$3"
    # Ensure log file path is set before trying to write
    if [[ -n "$LOG_FILE" ]]; then
        echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] ${color}[${level}] ${message}${NC}" | tee -a "$LOG_FILE"
    else
         echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] ${color}[${level}] ${message}${NC}" # Log to stdout only before log file is set
    fi
}

info() { log_msg "INFO" "$BLUE" "$1"; }
warn() { log_msg "WARN" "$YELLOW" "$1"; }
error() { log_msg "ERROR" "$RED" "$1"; }
success() { log_msg "SUCCESS" "$GREEN" "$1"; }
step() { echo; log_msg "STEP" "$GREEN" "$1"; } # Add newline before step

# Spinner function
# Usage:
# start_spinner "Doing something..."
# sleep 5 # Your command here
# stop_spinner $? # Pass exit status of command
spinner_pid=
spinner_chars="/-\|"
start_spinner() {
    local msg="$1..."
    # Use stderr for spinner so it doesn't interfere with command output redirection
    echo -n -e "${BLUE}[BUSY] ${msg}${NC} " >&2
    tput civis -- invisible # Hide cursor
    spinner_pid=
    (while true; do for i in $(seq 0 3); do echo -n -e "${spinner_chars:$i:1}" >&2; sleep 0.1; echo -ne "\b" >&2; done; done) &
    spinner_pid=$!
    # Disown the process so closing the script doesn't complain
    disown $spinner_pid &>/dev/null
}

stop_spinner() {
    local exit_status=$1
    if [[ -z "$spinner_pid" ]]; then
        # If spinner wasn't started (e.g., tool check failed), just return
        return
    fi
    # Kill the spinner background process
    kill $spinner_pid &>/dev/null
    wait $spinner_pid &>/dev/null # Prevent "Terminated" message
    tput cnorm -- normal # Restore cursor
    # Overwrite spinner message with status
    echo -ne "\r" >&2 # Move cursor to beginning of line
    if [[ $exit_status -eq 0 ]]; then
        echo -e "${GREEN}[DONE]${NC}                                                        " >&2 # Clear line with spaces
    else
        echo -e "${RED}[FAIL]${NC}                                                        " >&2 # Clear line with spaces
    fi
}

# Check if a command-line tool is available
check_tool() {
    local tool_name="$1"
    local required="$2" # Optional: 'required' or 'optional'
    if ! command -v "$tool_name" &> /dev/null; then
        if [[ "$required" == "required" ]]; then
            error "'$tool_name' command not found, but it is required. Please install it. Exiting."
            exit 1
        else
            # Don't log warning here, let the calling function decide based on whether the step runs
            return 1 # Indicate tool not found
        fi
    fi
    return 0 # Indicate tool found
}

# Check GitHub CLI authentication
check_gh_auth() {
    info "Checking GitHub CLI authentication..."
    if ! gh auth status &> /dev/null; then
        error "GitHub CLI 'gh' is not authenticated. Please run 'gh auth login' and try again. Exiting."
        exit 1
    fi
    success "GitHub CLI is authenticated."
}

# Load configuration from file
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        info "Loading configuration from $CONFIG_FILE"
        # Read key=value pairs, ignoring comments and empty lines
        while IFS='=' read -r key value; do
            # Remove leading/trailing whitespace and quotes
            key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/^"//;s/"$//;s/^'\''//;s/'\''$//')

            if [[ -n "$key" && ! "$key" =~ ^# && -n "$value" ]]; then
                case "$key" in
                    GITHUB_TOKEN) GITHUB_TOKEN_VAR="$value" ;;
                    # Add other config keys here if needed
                    *) warn "Unknown configuration key in $CONFIG_FILE: $key" ;;
                esac
            fi
        done < <(grep -v '^[[:space:]]*#' "$CONFIG_FILE" | grep '=') # Process lines with '=' after removing comments
        if [[ -n "$GITHUB_TOKEN_VAR" ]]; then
             info "Loaded GITHUB_TOKEN from config file."
        fi
    else
        info "Configuration file ($CONFIG_FILE) not found, using defaults and environment variables."
    fi

    # Prioritize environment variable if both exist
    if [[ -n "$GITHUB_TOKEN" ]]; then
         GITHUB_TOKEN_VAR="$GITHUB_TOKEN"
         info "Using GITHUB_TOKEN from environment variable (overrides config file)."
    fi

     if [[ -z "$GITHUB_TOKEN_VAR" ]]; then
        warn "GITHUB_TOKEN not found in environment or config file ($CONFIG_FILE). You might encounter stricter rate limits."
    else
        # Export the token so 'gh' and potentially other tools can use it
        export GITHUB_TOKEN="$GITHUB_TOKEN_VAR"
        info "GITHUB_TOKEN is set for use by tools."
    fi
}


# Check GitHub API rate limits
check_rate_limit() {
    info "Checking GitHub API rate limit..."
    local limit_info exit_status
    start_spinner "Querying GitHub API for rate limit"
    limit_info=$(gh api rate_limit --jq '.resources.core' 2>&1)
    exit_status=$?
    stop_spinner $exit_status

    if [[ $exit_status -ne 0 ]]; then
        warn "Could not check rate limit. Error: $limit_info. Proceeding with caution."
        return
    fi
    local remaining=$(echo "$limit_info" | jq -r '.remaining')
    local limit=$(echo "$limit_info" | jq -r '.limit')
    local reset_timestamp=$(echo "$limit_info" | jq -r '.reset')
    local reset_time=$(date -d @"$reset_timestamp" '+%Y-%m-%d %H:%M:%S')

    info "API Rate Limit: $remaining/$limit remaining. Resets at $reset_time."
    if [[ "$remaining" -lt 50 ]]; then # Adjust threshold as needed
        warn "Low API rate limit remaining ($remaining). Consider waiting or using a GITHUB_TOKEN."
    fi
}

# Add findings to JSON summary report
add_to_json_summary() {
    local key="$1"
    local value="$2"
    # Use jq to add or update the key-value pair in the JSON file
    # Creates the file with an initial {} if it doesn't exist
    jq --arg key "$key" --argjson value "$value" '. + {($key): $value}' "$SUMMARY_REPORT_JSON_FILE" > tmp.$$.json && mv tmp.$$.json "$SUMMARY_REPORT_JSON_FILE"
}

# --- Core Recon Functions ---

# Step 1: GitHub Dorking
run_github_dorking() {
    step "1: Running GitHub Code Search Dorking..."
    local dork_output_dir="$OUT_DIR/dorking"
    local dork_output_file="$dork_output_dir/code-search-results.md"
    mkdir -p "$dork_output_dir"

    info "Searching for common secrets patterns using 'gh search code'..."
    echo "# GitHub Dorking Results for $GH_TARGET" > "$dork_output_file"
    echo "**Timestamp:** $(date)" >> "$dork_output_file"
    echo >> "$dork_output_file" # Newline

    local total_found_count=0
    local dork_results=() # Array to store JSON results

    for dork in "${GITHUB_DORKS[@]}"; do
        info "Searching for: org:$GH_TARGET $dork"
        local search_results exit_status
        start_spinner "Searching dork: $dork"
        # Use process substitution to capture output and check exit status
        search_results=$(gh search code "org:$GH_TARGET $dork" --limit 10 --json url,path,repository 2>&1)
        exit_status=$?
        stop_spinner $exit_status

        if [[ $exit_status -ne 0 ]]; then
            warn "'gh search code' command failed for dork: $dork. Error: $search_results. Skipping."
            echo "## Dork: \`$dork\`" >> "$dork_output_file"
            echo "**FAILED**: Error during search." >> "$dork_output_file"
            echo '---' >> "$dork_output_file"
            dork_results+=("{\"dork\": \"$dork\", \"status\": \"failed\", \"error\": \"$search_results\"}")
            continue
        fi

        # Check if results are empty (jq returns empty or null for no results)
        if [[ -z "$search_results" || "$search_results" == "null" || "$search_results" == "[]" ]]; then
             info "No results found for dork: $dork"
             echo "## Dork: \`$dork\`" >> "$dork_output_file"
             echo "_No results found._" >> "$dork_output_file"
             dork_results+=("{\"dork\": \"$dork\", \"status\": \"no_results\", \"count\": 0}")
        else
            local count=$(echo "$search_results" | jq length)
            info "Found $count results for dork: $dork"
            echo "## Dork: \`$dork\` ($count results)" >> "$dork_output_file"
            echo '```json' >> "$dork_output_file"
            echo "$search_results" >> "$dork_output_file"
            echo '```' >> "$dork_output_file"
            total_found_count=$((total_found_count + count))
            # Add results to JSON array (escape quotes in dork for valid JSON)
            local escaped_dork=$(echo "$dork" | sed 's/"/\\"/g')
            dork_results+=("{\"dork\": \"$escaped_dork\", \"status\": \"found\", \"count\": $count, \"results\": $search_results}")
        fi
        echo '---' >> "$dork_output_file"
        sleep 1 # Shorter sleep with spinner
    done

    success "Dorking complete. Found potential items in $total_found_count results across all dorks. Saved to $dork_output_file"
    echo "- [GitHub Dorking](#github-dorking): Found potential items in $total_found_count results ([details]($dork_output_file))" >> "$SUMMARY_REPORT_MD_FILE"
    # Convert bash array of JSON strings into a single valid JSON array string
    local json_array_string=$(printf '%s\n' "${dork_results[@]}" | paste -sd ',')
    add_to_json_summary "github_dorking" "{\"total_found_count\": $total_found_count, \"details\": [$json_array_string]}"
}

# Step 2: Clone Repositories
run_repo_cloning() {
    step "2: Cloning Public Repositories..."
    local repos_list_file="$OUT_DIR/repos-list.txt"
    local repos_dir="$OUT_DIR/repos"
    mkdir -p "$repos_dir"

    info "Fetching list of public repositories for '$GH_TARGET'..."
    start_spinner "Fetching repo list"
    local repo_list_output exit_status
    repo_list_output=$(gh repo list "$GH_TARGET" --limit 1000 --source --json name,url --jq '.[].url' 2>&1 > "$repos_list_file")
    exit_status=$?
    stop_spinner $exit_status

    if [[ $exit_status -ne 0 ]]; then
        error "Failed to fetch repository list for '$GH_TARGET'. Error: $repo_list_output. Skipping cloning and local analysis."
        RUN_SECRETS_SCAN=false; RUN_TRIVY_FS=false; RUN_ENDPOINT_EXTRACTION=false; RUN_SUBDOMAIN_EXTRACTION=false
        add_to_json_summary "repo_cloning" '{"status": "failed_list_fetch"}'
        return 1
    fi

    local repo_count=$(wc -l < "$repos_list_file")
    if [[ "$repo_count" -eq 0 ]]; then
        warn "No public repositories found for '$GH_TARGET'. Skipping cloning and local analysis."
        RUN_SECRETS_SCAN=false; RUN_TRIVY_FS=false; RUN_ENDPOINT_EXTRACTION=false; RUN_SUBDOMAIN_EXTRACTION=false
        add_to_json_summary "repo_cloning" '{"status": "no_repos_found", "count": 0}'
        return 1
    fi

    info "Found $repo_count public repositories. Cloning into '$repos_dir' directory..."
    local clone_opts="" # No --quiet with spinner
    if [[ "$FULL_CLONE" = false ]]; then
        clone_opts="$clone_opts --depth=1"
        info "Using shallow clones (--depth=1). For full history analysis, use --full-clone."
    else
        info "Using full clones. This may take significantly more time and disk space."
    fi

    local CLONE_COUNT=0
    local FAIL_COUNT=0
    while IFS= read -r url; do
        local repo_name=$(basename "$url" .git)
        # info "Cloning $repo_name..." # Replaced by spinner
        start_spinner "Cloning $repo_name"
        local clone_output exit_status
        # Redirect stderr to capture git errors but allow spinner on stderr
        clone_output=$(git clone $clone_opts "$url" "$repos_dir/$repo_name" 2>&1)
        exit_status=$?
        stop_spinner $exit_status
        if [[ $exit_status -ne 0 ]]; then
            warn "Failed to clone $url. Error: $clone_output. Skipping."
            ((FAIL_COUNT++))
        else
            ((CLONE_COUNT++))
        fi
    done < "$repos_list_file"

    success "Cloning complete. Successfully cloned $CLONE_COUNT repositories. Failed to clone $FAIL_COUNT."
    echo "- [Repository Cloning](#repository-cloning): Cloned $CLONE_COUNT repositories." >> "$SUMMARY_REPORT_MD_FILE"
    [[ "$FAIL_COUNT" -gt 0 ]] && echo "  - Failed to clone $FAIL_COUNT repositories." >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "repo_cloning" "{\"status\": \"completed\", \"cloned_count\": $CLONE_COUNT, \"failed_count\": $FAIL_COUNT}"


    if [[ "$CLONE_COUNT" -eq 0 ]]; then
        warn "No repositories were successfully cloned. Skipping local analysis steps."
        RUN_SECRETS_SCAN=false; RUN_TRIVY_FS=false; RUN_ENDPOINT_EXTRACTION=false; RUN_SUBDOMAIN_EXTRACTION=false
        return 1
    fi
    return 0
}

# Step 3: Secrets Scanning (Gitleaks & TruffleHog)
run_secrets_scanning() {
    step "3: Running Secrets Scanning..."
    local repos_dir="$OUT_DIR/repos"
    local gitleaks_dir="$OUT_DIR/secrets/gitleaks"
    local trufflehog_dir="$OUT_DIR/secrets/trufflehog"
    mkdir -p "$gitleaks_dir" "$trufflehog_dir"

    local gitleaks_found_total=0
    local trufflehog_found_total=0
    local gitleaks_status="skipped"
    local trufflehog_status="skipped"

    # Run Gitleaks
    if check_tool "gitleaks" "optional"; then
        info "Running Gitleaks scan..."
        gitleaks_status="running"
        for repo_path in "$repos_dir"/*; do
            if [ -d "$repo_path/.git" ]; then
                local repo_name=$(basename "$repo_path")
                local report_file="$gitleaks_dir/${repo_name}-report.json"
                start_spinner "Gitleaks scanning $repo_name"
                local scan_output exit_status
                # Capture output in case of errors, run verbosely
                scan_output=$(gitleaks detect -s "$repo_path" --report-path "$report_file" --report-format json --no-banner -v 2>&1)
                exit_status=$?
                stop_spinner $exit_status
                if [[ $exit_status -ne 0 && $exit_status -ne 1 ]]; then # Gitleaks exits 1 if findings found, 0 if none, >1 on error
                    warn "Gitleaks scan failed for $repo_name. Error: $scan_output"
                    rm -f "$report_file" # Remove potentially incomplete report
                elif [[ -s "$report_file" ]]; then
                    local count=$(jq length "$report_file")
                    if [[ "$count" -gt 0 ]]; then
                         warn "Gitleaks found $count potential secrets in $repo_name."
                         gitleaks_found_total=$((gitleaks_found_total + count))
                    fi
                fi
            fi
        done
        success "Gitleaks scan complete. Found $gitleaks_found_total potential secrets."
        gitleaks_status="completed"
    else
        warn "Gitleaks not found, skipping Gitleaks scan."
        gitleaks_status="skipped_not_found"
    fi

    # Run TruffleHog
    if check_tool "trufflehog" "optional"; then
        info "Running TruffleHog scan (can be slow)..."
        trufflehog_status="running"
        for repo_path in "$repos_dir"/*; do
             if [ -d "$repo_path" ]; then
                local repo_name=$(basename "$repo_path")
                local report_file="$trufflehog_dir/${repo_name}-report.json"
                start_spinner "TruffleHog scanning $repo_name"
                local scan_output exit_status
                # Redirect stdout to file, capture stderr
                scan_output=$(trufflehog filesystem --directory "$repo_path" --json 2>&1 > "$report_file")
                exit_status=$?
                stop_spinner $exit_status
                 if [[ $exit_status -ne 0 ]]; then
                    warn "Trufflehog scan failed for $repo_name. Error: $scan_output"
                    rm -f "$report_file"
                 elif [[ -s "$report_file" && "$(jq 'length > 0' "$report_file")" == "true" ]]; then
                    local count=$(jq length "$report_file")
                    warn "TruffleHog found $count potential secrets in $repo_name."
                    trufflehog_found_total=$((trufflehog_found_total + count))
                else
                    # Clean up empty report files
                    rm -f "$report_file"
                fi
            fi
        done
        success "TruffleHog scan complete. Found $trufflehog_found_total potential secrets."
        trufflehog_status="completed"
    else
        warn "TruffleHog not found, skipping TruffleHog scan."
        trufflehog_status="skipped_not_found"
    fi

    echo "- [Secrets Scanning](#secrets-scanning):" >> "$SUMMARY_REPORT_MD_FILE"
    echo "  - Gitleaks: Found $gitleaks_found_total potential secrets ([details]($gitleaks_dir/))" >> "$SUMMARY_REPORT_MD_FILE"
    echo "  - TruffleHog: Found $trufflehog_found_total potential secrets ([details]($trufflehog_dir/))" >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "secrets_scanning" "{\"gitleaks\": {\"status\": \"$gitleaks_status\", \"found_count\": $gitleaks_found_total}, \"trufflehog\": {\"status\": \"$trufflehog_status\", \"found_count\": $trufflehog_found_total}}"
}

# Step 4: Filesystem Vulnerability Scanning (Trivy FS)
run_trivy_scan() {
    step "4: Running Filesystem Vulnerability Scanning (Trivy FS)..."
     if ! check_tool "trivy" "optional"; then
        warn "Trivy not found. Skipping filesystem scan."
        echo "- [Filesystem Scan (Trivy)](#filesystem-scan-trivy): Skipped (trivy not found)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "trivy_fs_scan" '{"status": "skipped_not_found"}'
        return 1
    fi

    local repos_dir="$OUT_DIR/repos"
    local trivy_dir="$OUT_DIR/trivy-fs-results"
    mkdir -p "$trivy_dir"
    local total_vulns=0
    local status="running"

    info "Running Trivy filesystem scan on cloned repositories (can be slow)..."
    start_spinner "Trivy scanning all cloned repos"
    local scan_output exit_status
    # Scan the entire repos directory, output JSON, ignore unfixed, medium+ severity
    scan_output=$(trivy fs --format json --output "$trivy_dir/trivy_fs_report.json" --ignore-unfixed --severity MEDIUM,HIGH,CRITICAL "$repos_dir" 2>&1)
    exit_status=$?
    stop_spinner $exit_status

    if [[ $exit_status -ne 0 ]]; then
        warn "Trivy filesystem scan failed. Error: $scan_output"
        rm -f "$trivy_dir/trivy_fs_report.json"
        status="failed"
    elif [[ -s "$trivy_dir/trivy_fs_report.json" ]]; then
        # Count vulnerabilities by summing lengths of Vulnerabilities arrays
        total_vulns=$(jq '[.Results[]? | select(.Vulnerabilities) | .Vulnerabilities[]?] | length' "$trivy_dir/trivy_fs_report.json")
        [[ -z "$total_vulns" ]] && total_vulns=0 # Handle null case
        success "Trivy filesystem scan complete. Found $total_vulns potential vulnerabilities (Medium+). Report saved."
        status="completed"
    else
        success "Trivy filesystem scan complete. No vulnerabilities found (Medium+)."
        status="completed_no_vulns"
    fi

    echo "- [Filesystem Scan (Trivy)](#filesystem-scan-trivy): Found $total_vulns vulnerabilities (Medium+) ([details]($trivy_dir/trivy_fs_report.json))" >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "trivy_fs_scan" "{\"status\": \"$status\", \"found_count\": $total_vulns}"
}


# Step 5: Extract JS Endpoints
run_endpoint_extraction() {
    step "5: Extracting Potential Endpoints from JS Files..."
    local repos_dir="$OUT_DIR/repos"
    local endpoints_dir="$OUT_DIR/endpoints"
    local js_endpoints_file="$endpoints_dir/js_endpoints_sorted.txt"
    mkdir -p "$endpoints_dir"

    info "Searching for URL patterns and paths in *.js files..."
    start_spinner "Extracting JS endpoints"
    find "$repos_dir/" -name "*.js" -type f -exec cat {} + 2>/dev/null | \
        grep -Eoi '"(https?://|/)[a-zA-Z0-9./?=_%~&+-]*"' | \
        sed -e 's/^"//' -e 's/"$//' | \
        sort -u > "$js_endpoints_file"
    local exit_status=$? # Check grep/sed/sort pipeline status (less reliable)
    stop_spinner $exit_status

    local count=$(wc -l < "$js_endpoints_file")
    success "Extracted $count potential unique JS endpoints to $js_endpoints_file"
    echo "- [JS Endpoint Extraction](#js-endpoint-extraction): Found $count potential endpoints ([details]($js_endpoints_file))" >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "js_endpoint_extraction" "{\"status\": \"completed\", \"found_count\": $count}"
}

# Step 6: Extract Subdomains from Code
run_subdomain_extraction() {
    step "6: Extracting Potential Subdomains/Domains from Code..."
    local repos_dir="$OUT_DIR/repos"
    local subdomains_dir="$OUT_DIR/subdomains"
    local code_subdomains_file="$subdomains_dir/subdomains_from_code.txt"
    mkdir -p "$subdomains_dir"

    info "Using grep to find potential FQDN patterns in cloned code..."
    start_spinner "Grepping for domains in code"
    grep -Eohr "[a-zA-Z0-9]+([.-][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}" "$repos_dir/" | \
        sort -u > "$code_subdomains_file"
    local exit_status=$?
    stop_spinner $exit_status

    local count=$(wc -l < "$code_subdomains_file")
    success "Extracted $count potential unique domains/subdomains from code to $code_subdomains_file"
    warn "Review this file manually as it may contain non-target or public domains."
    echo "- [Subdomain Extraction (Code)](#subdomain-extraction-code): Found $count potential domains ([details]($code_subdomains_file))" >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "subdomain_extraction_code" "{\"status\": \"completed\", \"found_count\": $count}"
}

# Step 7: Subdomain Enumeration with Subfinder
run_subfinder_enum() {
    step "7: Running Subdomain Enumeration (Subfinder)..."
    if ! check_tool "subfinder" "optional"; then
        warn "Subfinder not found. Skipping Subfinder enumeration."
        echo "- [Subdomain Enumeration (Subfinder)](#subdomain-enumeration-subfinder): Skipped (subfinder not found)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "subfinder_enum" '{"status": "skipped_not_found"}'
        return 1
    fi

    if [[ ${#TARGET_DOMAINS[@]} -eq 0 ]]; then
        warn "No target domains specified with --domain flag. Skipping Subfinder enumeration."
        echo "- [Subdomain Enumeration (Subfinder)](#subdomain-enumeration-subfinder): Skipped (no --domain specified)" >> "$SUMMARY_REPORT_MD_FILE"
         add_to_json_summary "subfinder_enum" '{"status": "skipped_no_domain"}'
        return 1
    fi

    local subdomains_dir="$OUT_DIR/subdomains"
    local subfinder_output_file="$subdomains_dir/subdomains_from_subfinder.txt"
    mkdir -p "$subdomains_dir"

    info "Running subfinder on specified domains: ${TARGET_DOMAINS[*]}"
    local domain_list_file=$(mktemp)
    printf "%s\n" "${TARGET_DOMAINS[@]}" > "$domain_list_file"

    start_spinner "Running subfinder"
    local scan_output exit_status
    scan_output=$(subfinder -dL "$domain_list_file" -o "$subfinder_output_file" -silent 2>&1)
    exit_status=$?
    stop_spinner $exit_status
    rm "$domain_list_file" # Clean up temp file

    if [[ $exit_status -ne 0 ]]; then
        warn "Subfinder command failed. Error: $scan_output"
        # Don't assume file wasn't created, check its status
    fi

    local count=0
    if [[ -f "$subfinder_output_file" ]]; then
        count=$(wc -l < "$subfinder_output_file")
    else
         warn "Subfinder did not produce an output file."
         touch "$subfinder_output_file" # Create empty file
    fi

    success "Subfinder enumeration complete. Found $count subdomains. Saved to $subfinder_output_file"
    echo "- [Subdomain Enumeration (Subfinder)](#subdomain-enumeration-subfinder): Found $count subdomains ([details]($subfinder_output_file))" >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "subfinder_enum" "{\"status\": \"completed\", \"found_count\": $count}"
}

# Step 8: Combine and Probe Live Hosts (httpx)
run_httpx_probing() {
    step "8: Probing for Live Hosts (httpx)..."
     if ! check_tool "httpx" "optional"; then
        warn "httpx not found. Skipping live host probing."
        echo "- [Live Host Probing (httpx)](#live-host-probing-httpx): Skipped (httpx not found)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "httpx_probing" '{"status": "skipped_not_found"}'
        # Skip dependent steps
        RUN_NAABU=false; RUN_GAU=false; RUN_GOWITNESS=false; RUN_NUCLEI=false
        return 1
    fi

    local subdomains_dir="$OUT_DIR/subdomains"
    local httpx_dir="$OUT_DIR/httpx-results"
    local combined_subdomains_file="$subdomains_dir/subdomains_combined_unique.txt"
    local live_hosts_file="$httpx_dir/live_hosts_httpx.txt"
    mkdir -p "$httpx_dir"

    info "Combining unique subdomains from code and subfinder..."
    cat "$subdomains_dir/subdomains_from_code.txt" "$subdomains_dir/subdomains_from_subfinder.txt" 2>/dev/null | \
        sort -u > "$combined_subdomains_file"

    local combined_count=$(wc -l < "$combined_subdomains_file")
    info "Total unique potential domains/subdomains to probe: $combined_count"

    if [[ ! -s "$combined_subdomains_file" ]]; then
        warn "No domains/subdomains found to probe. Skipping httpx and dependent steps."
        echo "- [Live Host Probing (httpx)](#live-host-probing-httpx): Skipped (no input domains)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "httpx_probing" '{"status": "skipped_no_input"}'
        RUN_NAABU=false; RUN_GAU=false; RUN_GOWITNESS=false; RUN_NUCLEI=false
        return 1
    fi

    info "Running httpx on combined list..."
    start_spinner "Running httpx"
    local scan_output exit_status
    scan_output=$(httpx -silent -l "$combined_subdomains_file" -o "$live_hosts_file" \
          -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
          -threads 50 -status-code -title -tech-detect -json \
          2>&1 > "$httpx_dir/live_hosts_httpx.jsonl") # Also save JSON output
    exit_status=$?
    stop_spinner $exit_status

     if [[ $exit_status -ne 0 ]]; then
        warn "httpx command failed. Error: $scan_output"
        # Don't assume file wasn't created
    fi

    local live_count=0
    if [[ -f "$live_hosts_file" ]]; then
        live_count=$(wc -l < "$live_hosts_file")
    else
        warn "httpx did not produce a text output file."
        touch "$live_hosts_file" # Create empty file
    fi

    success "httpx probing complete. Found $live_count potentially live hosts. Saved to $live_hosts_file"
    echo "- [Live Host Probing (httpx)](#live-host-probing-httpx): Found $live_count live hosts ([details]($live_hosts_file))" >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "httpx_probing" "{\"status\": \"completed\", \"found_count\": $live_count}"

    # Check if any live hosts were found before enabling subsequent steps
    if [[ "$live_count" -eq 0 ]]; then
        warn "No live hosts discovered by httpx. Skipping dependent steps (Naabu, Gau, Gowitness, Nuclei)."
        RUN_NAABU=false; RUN_GAU=false; RUN_GOWITNESS=false; RUN_NUCLEI=false
        return 1
    fi
    return 0
}

# Step 9: Port Scanning (Naabu)
run_naabu_scan() {
    step "9: Running Port Scanning (Naabu)..."
    if ! check_tool "naabu" "optional"; then
        warn "Naabu not found. Skipping port scan."
        echo "- [Port Scanning (Naabu)](#port-scanning-naabu): Skipped (naabu not found)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "naabu_scan" '{"status": "skipped_not_found"}'
        return 1
    fi

    local httpx_dir="$OUT_DIR/httpx-results"
    local naabu_dir="$OUT_DIR/naabu-results"
    local live_hosts_file="$httpx_dir/live_hosts_httpx.txt" # Use httpx output
    local naabu_output_file="$naabu_dir/naabu_portscan_results.txt"
    mkdir -p "$naabu_dir"

    # Extract hosts/IPs from httpx output (assuming URL is first column, extract host)
    # This might need refinement depending on httpx output format and if IPs are needed
    sed 's|.*://||; s|/.*||; s|:.*||' "$live_hosts_file" | sort -u > "$naabu_dir/hosts_for_naabu.tmp"

    if [[ ! -s "$naabu_dir/hosts_for_naabu.tmp" ]]; then
        warn "Could not extract hosts for Naabu. Skipping port scan."
        rm "$naabu_dir/hosts_for_naabu.tmp"
        echo "- [Port Scanning (Naabu)](#port-scanning-naabu): Skipped (no hosts extracted)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "naabu_scan" '{"status": "skipped_no_input"}'
        return 1
    fi

    info "Running Naabu port scan on discovered live hosts (Top 100 ports)..."
    start_spinner "Running naabu"
    local scan_output exit_status
    # Scan top 100 ports silently
    scan_output=$(naabu -list "$naabu_dir/hosts_for_naabu.tmp" -top-ports 100 -silent -o "$naabu_output_file" 2>&1)
    exit_status=$?
    stop_spinner $exit_status
    rm "$naabu_dir/hosts_for_naabu.tmp"

    if [[ $exit_status -ne 0 ]]; then
        warn "Naabu scan failed. Error: $scan_output"
    fi

    local open_port_count=0
    if [[ -f "$naabu_output_file" ]]; then
         open_port_count=$(wc -l < "$naabu_output_file")
    else
        warn "Naabu did not produce an output file."
        touch "$naabu_output_file" # Create empty file
    fi

    success "Naabu port scan complete. Found $open_port_count open ports (Top 100). Saved to $naabu_output_file"
    echo "- [Port Scanning (Naabu)](#port-scanning-naabu): Found $open_port_count open ports ([details]($naabu_output_file))" >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "naabu_scan" "{\"status\": \"completed\", \"open_port_count\": $open_port_count}"
}

# Step 10: Discover URLs (gau)
run_gau_discovery() {
    step "10: Discovering Known URLs (gau)..."
    if ! check_tool "gau" "optional"; then
        warn "gau not found. Skipping URL discovery."
        echo "- https://medium.com/@enessyibrahim/mastering-reconnaissance-with-project-discovery-99d7a21e299a(#url-discovery-gau): Skipped (gau not found)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "gau_discovery" '{"status": "skipped_not_found"}'
        return 1
    fi

    local httpx_dir="$OUT_DIR/httpx-results"
    local endpoints_dir="$OUT_DIR/endpoints"
    local live_hosts_file="$httpx_dir/live_hosts_httpx.txt" # Use httpx output containing URLs
    local gau_output_file="$endpoints_dir/urls_from_gau.txt"
    mkdir -p "$endpoints_dir"

    # Extract just the URLs (first column) from httpx output if it exists and has content
    if [[ -s "$live_hosts_file" ]]; then
        awk '{print $1}' "$live_hosts_file" > "$endpoints_dir/live_urls_for_gau.tmp"

        if [[ -s "$endpoints_dir/live_urls_for_gau.tmp" ]]; then
             info "Running gau on live hosts found by httpx..."
             start_spinner "Running gau"
             local scan_output exit_status
             scan_output=$(cat "$endpoints_dir/live_urls_for_gau.tmp" | gau --threads 5 --subs 2>&1 > "$gau_output_file")
             exit_status=$?
             stop_spinner $exit_status
             rm "$endpoints_dir/live_urls_for_gau.tmp" # Clean up temp file
             if [[ $exit_status -ne 0 ]]; then
                warn "gau command failed. Error: $scan_output"
             fi
        else
            warn "Could not extract URLs from httpx output. Skipping gau."
            rm "$endpoints_dir/live_urls_for_gau.tmp"
            touch "$gau_output_file" # Create empty file
        fi
    else
        warn "No live hosts file ($live_hosts_file) found or empty. Skipping gau."
        touch "$gau_output_file" # Create empty file
    fi

    local count=0
     if [[ -f "$gau_output_file" ]]; then
        count=$(wc -l < "$gau_output_file")
    fi
    success "gau URL discovery complete. Found $count URLs. Saved to $gau_output_file"
    echo "- https://medium.com/@enessyibrahim/mastering-reconnaissance-with-project-discovery-99d7a21e299a(#url-discovery-gau): Found $count URLs ([details]($gau_output_file))" >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "gau_discovery" "{\"status\": \"completed\", \"found_count\": $count}"
}

# Step 11: Screenshot Live Hosts (gowitness)
run_gowitness_screenshots() {
    step "11: Screenshotting Live Web Applications (gowitness)..."
     if ! check_tool "gowitness" "optional"; then
        warn "gowitness not found. Skipping screenshotting."
        echo "- [Screenshotting (gowitness)](#screenshotting-gowitness): Skipped (gowitness not found)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "gowitness_screenshots" '{"status": "skipped_not_found"}'
        return 1
    fi

    local httpx_dir="$OUT_DIR/httpx-results"
    local gowitness_dir="$OUT_DIR/gowitness-results"
    local live_hosts_file="$httpx_dir/live_hosts_httpx.txt" # Use httpx output
    mkdir -p "$gowitness_dir" "$gowitness_dir/screenshots" # Ensure screenshot dir exists

    if [[ ! -s "$live_hosts_file" ]]; then
        warn "No live hosts file ($live_hosts_file) found or empty. Skipping gowitness."
        echo "- [Screenshotting (gowitness)](#screenshotting-gowitness): Skipped (no input hosts)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "gowitness_screenshots" '{"status": "skipped_no_input"}'
        return 1
    fi

    info "Running gowitness on live hosts..."
    awk '{print $1}' "$live_hosts_file" > "$gowitness_dir/urls_for_gowitness.tmp"

    if [[ -s "$gowitness_dir/urls_for_gowitness.tmp" ]]; then
        start_spinner "Running gowitness"
        local scan_output exit_status
        scan_output=$(gowitness file -f "$gowitness_dir/urls_for_gowitness.tmp" \
            --destination "$gowitness_dir/screenshots/" \
            --db-path "$gowitness_dir/gowitness.sqlite3" \
            --threads 5 2>&1) # Capture output
         exit_status=$?
         stop_spinner $exit_status
         rm "$gowitness_dir/urls_for_gowitness.tmp"
         if [[ $exit_status -ne 0 ]]; then
            warn "gowitness command failed. Error: $scan_output"
         fi
        success "gowitness screenshotting complete. Results in $gowitness_dir"
        echo "- [Screenshotting (gowitness)](#screenshotting-gowitness): Completed ([details]($gowitness_dir/))" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "gowitness_screenshots" '{"status": "completed"}'
    else
        warn "Could not extract URLs for gowitness. Skipping."
        rm "$gowitness_dir/urls_for_gowitness.tmp"
        echo "- [Screenshotting (gowitness)](#screenshotting-gowitness): Skipped (could not extract URLs)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "gowitness_screenshots" '{"status": "skipped_no_urls"}'
    fi
}

# Step 12: Vulnerability Scanning (Nuclei)
run_nuclei_scan() {
    step "12: Running Vulnerability Scanning (Nuclei)..."
    if ! check_tool "nuclei" "optional"; then
        warn "Nuclei not found. Skipping vulnerability scan."
        echo "- [Vulnerability Scanning (Nuclei)](#vulnerability-scanning-nuclei): Skipped (nuclei not found)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "nuclei_scan" '{"status": "skipped_not_found"}'
        return 1
    fi

    local httpx_dir="$OUT_DIR/httpx-results"
    local nuclei_dir="$OUT_DIR/nuclei-results"
    local live_hosts_file="$httpx_dir/live_hosts_httpx.txt" # Use httpx output
    local nuclei_report_file="$nuclei_dir/nuclei_scan_report.txt"
    local nuclei_report_json_file="$nuclei_dir/nuclei_scan_report.jsonl"
    mkdir -p "$nuclei_dir"

    if [[ ! -s "$live_hosts_file" ]]; then
        warn "No live hosts file ($live_hosts_file) found or empty. Skipping Nuclei scan."
        echo "- [Vulnerability Scanning (Nuclei)](#vulnerability-scanning-nuclei): Skipped (no input hosts)" >> "$SUMMARY_REPORT_MD_FILE"
        add_to_json_summary "nuclei_scan" '{"status": "skipped_no_input"}'
        return 1
    fi

    info "Running Nuclei on live hosts using templates: $NUCLEI_TEMPLATES (excluding: $NUCLEI_EXCLUSIONS)..."
    start_spinner "Running nuclei"
    local scan_output exit_status
    scan_output=$(nuclei -l "$live_hosts_file" \
           -t "$NUCLEI_TEMPLATES" \
           -etags "$NUCLEI_EXCLUSIONS" \
           -stats -silent \
           -o "$nuclei_report_file" \
           -jsonl -o "$nuclei_report_json_file" \
           -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
           2>&1) # Capture output
    exit_status=$?
    stop_spinner $exit_status

    if [[ $exit_status -ne 0 ]]; then
        warn "Nuclei scan potentially failed (check logs/output). Error: $scan_output"
        # Nuclei exit codes can vary, proceed to count findings
    fi

    local finding_count=0
    if [[ -f "$nuclei_report_file" ]]; then
        finding_count=$(wc -l < "$nuclei_report_file")
    else
        warn "Nuclei did not produce a text output file."
        touch "$nuclei_report_file" # Create empty file
    fi

    success "Nuclei scan complete. Found $finding_count potential findings. Report saved to $nuclei_report_file"
    echo "- [Vulnerability Scanning (Nuclei)](#vulnerability-scanning-nuclei): Found $finding_count potential findings ([details]($nuclei_report_file))" >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "nuclei_scan" "{\"status\": \"completed\", \"found_count\": $finding_count}"
}

# Step 13: Cleanup
run_cleanup() {
    step "13: Cleaning up cloned repositories..."
    local repos_dir="$OUT_DIR/repos"
    if [ -d "$repos_dir" ]; then
        info "Removing cloned repositories directory: $repos_dir"
        start_spinner "Removing repos directory"
        rm -rf "$repos_dir"
        local exit_status=$?
        stop_spinner $exit_status
        if [[ $exit_status -eq 0 ]]; then
            success "Cleanup complete."
            echo "- [Cleanup](#cleanup): Removed cloned repositories directory." >> "$SUMMARY_REPORT_MD_FILE"
            add_to_json_summary "cleanup" '{"status": "completed"}'
        else
            error "Failed to remove repositories directory."
            echo "- [Cleanup](#cleanup): Failed to remove cloned repositories directory." >> "$SUMMARY_REPORT_MD_FILE"
            add_to_json_summary "cleanup" '{"status": "failed"}'
        fi
    else
        info "Cloned repositories directory not found ($repos_dir). Nothing to clean up."
         echo "- [Cleanup](#cleanup): No repositories directory found to remove." >> "$SUMMARY_REPORT_MD_FILE"
         add_to_json_summary "cleanup" '{"status": "skipped_not_found"}'
    fi
}

# --- Argument Parsing ---
usage() {
    echo "Usage: $SCRIPT_NAME -t <target> [-o <out_dir>] [-c <config_file>] [-d <domain>] [--full-clone] [--cleanup] [skip_flags...]"
    echo ""
    echo "Required:"
    echo "  -t, --target <username/org>  GitHub username or organization to scan."
    echo ""
    echo "Options:"
    echo "  -o, --output <dir>           Output directory (default: ${DEFAULT_OUT_DIR_PREFIX}<target>)."
    echo "  -c, --config <file>          Configuration file (default: $DEFAULT_CONFIG_FILE)."
    echo "  -d, --domain <domain>        Target domain for focused subdomain enumeration (can be used multiple times)."
    echo "      --full-clone             Perform full git clones (default: shallow --depth=1)."
    echo "      --cleanup                Remove cloned 'repos/' directory after script completion."
    echo "      --skip-dorking           Skip GitHub code search dorking."
    echo "      --skip-cloning           Skip cloning repositories (also skips local analysis steps)."
    echo "      --skip-secrets           Skip Gitleaks and TruffleHog scans."
    echo "      --skip-trivy             Skip Trivy filesystem scan."
    echo "      --skip-endpoints         Skip JS endpoint extraction."
    echo "      --skip-subdomains-code   Skip subdomain extraction from code."
    echo "      --skip-subfinder         Skip subdomain enumeration using Subfinder."
    echo "      --skip-httpx             Skip live host probing using httpx (also skips naabu, gau, gowitness, nuclei)."
    echo "      --skip-naabu             Skip port scanning using Naabu."
    echo "      --skip-gau               Skip URL discovery using gau."
    echo "      --skip-gowitness         Skip screenshotting using gowitness."
    echo "      --skip-nuclei            Skip vulnerability scanning using Nuclei."
    echo "  -h, --help                   Show this help message."
    echo "  -v, --version                Show script version."
    echo ""
    echo "Example:"
    echo "  $SCRIPT_NAME -t MyOrg -d myorg.com -d myorg-prod.com -o ./myorg-recon --full-clone"
    echo "  $SCRIPT_NAME -t MyUser --skip-cloning --skip-secrets --skip-trivy"
    exit 1
}

# Use getopt for robust argument parsing
TEMP=$(getopt -o t:o:c:d:hv --long target:,output:,config:,domain:,full-clone,cleanup,skip-dorking,skip-cloning,skip-secrets,skip-trivy,skip-endpoints,skip-subdomains-code,skip-subfinder,skip-httpx,skip-naabu,skip-gau,skip-gowitness,skip-nuclei,help,version -n "$SCRIPT_NAME" -- "$@")

if [ $? != 0 ]; then error "Terminating... Invalid arguments." >&2; usage; fi

# Note the quotes around '$TEMP': they are essential!
eval set -- "$TEMP"
unset TEMP

while true; do
    case "$1" in
        '-t'|'--target') GH_TARGET="$2"; shift 2 ;;
        '-o'|'--output') OUT_DIR="$2"; shift 2 ;;
        '-c'|'--config') CONFIG_FILE="$2"; shift 2 ;;
        '-d'|'--domain') TARGET_DOMAINS+=("$2"); shift 2 ;; # Append to array
        '--full-clone') FULL_CLONE=true; shift ;;
        '--cleanup') CLEANUP_REPOS=true; shift ;;
        '--skip-dorking') RUN_DORKING=false; shift ;;
        '--skip-cloning') RUN_CLONING=false; shift ;;
        '--skip-secrets') RUN_SECRETS_SCAN=false; shift ;;
        '--skip-trivy') RUN_TRIVY_FS=false; shift ;;
        '--skip-endpoints') RUN_ENDPOINT_EXTRACTION=false; shift ;;
        '--skip-subdomains-code') RUN_SUBDOMAIN_EXTRACTION=false; shift ;;
        '--skip-subfinder') RUN_SUBFINDER=false; shift ;;
        '--skip-httpx') RUN_HTTPX=false; shift ;;
        '--skip-naabu') RUN_NAABU=false; shift ;;
        '--skip-gau') RUN_GAU=false; shift ;;
        '--skip-gowitness') RUN_GOWITNESS=false; shift ;;
        '--skip-nuclei') RUN_NUCLEI=false; shift ;;
        '-h'|'--help') usage ;;
        '-v'|'--version') echo "$SCRIPT_NAME Version $SCRIPT_VERSION"; exit 0 ;;
        '--') shift; break ;; # End of options
        *) error "Internal error! Unexpected option: $1"; usage ;;
    esac
done

# --- Validation and Setup ---

# Validate required arguments
if [[ -z "$GH_TARGET" ]]; then
    error "Target (-t or --target) is required."
    usage
fi

# Set default output directory if not provided
if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="${DEFAULT_OUT_DIR_PREFIX}${GH_TARGET}"
fi

# Create output directory and handle potential errors
mkdir -p "$OUT_DIR"
if [[ $? -ne 0 ]]; then
    error "Failed to create output directory: $OUT_DIR. Check permissions."
    exit 1
fi
# Use absolute path for output directory
OUT_DIR=$(realpath "$OUT_DIR")

# Setup logging path *before* logging starts
LOG_FILE="$OUT_DIR/recon-run-$(date +%Y%m%d-%H%M%S).log"
# Redirect stdout/stderr to screen and log file.
exec > >(tee -a "$LOG_FILE") 2>&1

# Setup Summary Report Files
SUMMARY_REPORT_MD_FILE="$OUT_DIR/summary-report.md"
SUMMARY_REPORT_JSON_FILE="$OUT_DIR/summary-report.json"
echo "{}" > "$SUMMARY_REPORT_JSON_FILE" # Initialize JSON file

echo "# GitHub Reconnaissance Summary Report for $GH_TARGET" > "$SUMMARY_REPORT_MD_FILE"
echo "**Generated:** $(date)" >> "$SUMMARY_REPORT_MD_FILE"
echo "**Output Directory:** \`$OUT_DIR\`" >> "$SUMMARY_REPORT_MD_FILE"
echo "**Log File:** \`$LOG_FILE\`" >> "$SUMMARY_REPORT_MD_FILE"
echo "**Config File:** \`$CONFIG_FILE\`" >> "$SUMMARY_REPORT_MD_FILE"
echo >> "$SUMMARY_REPORT_MD_FILE"
echo "## Execution Summary" >> "$SUMMARY_REPORT_MD_FILE"
# Add initial config to JSON summary
add_to_json_summary "target" "\"$GH_TARGET\""
add_to_json_summary "output_directory" "\"$OUT_DIR\""
add_to_json_summary "config_file" "\"$CONFIG_FILE\""
add_to_json_summary "target_domains" "$(printf '%s\n' "${TARGET_DOMAINS[@]}" | jq -R . | jq -s .)"
add_to_json_summary "options" "{\"full_clone\": $FULL_CLONE, \"cleanup\": $CLEANUP_REPOS}"


info "Starting Advanced GitHub Reconnaissance Script v$SCRIPT_VERSION"
info "Target: $GH_TARGET"
info "Output Directory: $OUT_DIR"
info "Log File: $LOG_FILE"
info "Config File: $CONFIG_FILE"
info "Summary Report (MD): $SUMMARY_REPORT_MD_FILE"
info "Summary Report (JSON): $SUMMARY_REPORT_JSON_FILE"
[[ ${#TARGET_DOMAINS[@]} -gt 0 ]] && info "Target Domains: ${TARGET_DOMAINS[*]}"
[[ "$FULL_CLONE" = true ]] && info "Full Clones: Enabled"
[[ "$CLEANUP_REPOS" = true ]] && info "Cleanup: Enabled"

# --- Prerequisite Checks & Config Loading ---
step "0: Checking Prerequisites & Loading Config..."
load_config # Load config file and GITHUB_TOKEN
check_tool "git" "required"; check_tool "gh" "required"; check_tool "jq" "required"
check_tool "trivy" "optional"; check_tool "gitleaks" "optional"; check_tool "trufflehog" "optional"
check_tool "subfinder" "optional"; check_tool "httpx" "optional"; check_tool "naabu" "optional"
check_tool "gau" "optional"; check_tool "gowitness" "optional"; check_tool "nuclei" "optional"
check_tool "tree" "optional"; check_tool "awk" "required"; check_tool "sed" "required"
check_tool "grep" "required"; check_tool "sort" "required"; check_tool "find" "required"
check_tool "wc" "required"; check_tool "date" "required"; check_tool "mktemp" "required"
check_tool "realpath" "required"; check_tool "tee" "required"; check_tool "kill" "required"
check_tool "wait" "required"; check_tool "tput" "optional" # For spinner visuals

check_gh_auth # Check gh login status
check_rate_limit # Check initial rate limit

# --- Main Execution Flow ---

start_time=$(date +%s)
add_to_json_summary "start_time" "\"$(date -Is)\""

# Add skip flags status to JSON summary
skip_flags_json=$(jq -n \
    --argjson dorking $RUN_DORKING \
    --argjson cloning $RUN_CLONING \
    --argjson secrets $RUN_SECRETS_SCAN \
    --argjson trivy $RUN_TRIVY_FS \
    --argjson endpoints $RUN_ENDPOINT_EXTRACTION \
    --argjson subcode $RUN_SUBDOMAIN_EXTRACTION \
    --argjson subfinder $RUN_SUBFINDER \
    --argjson httpx $RUN_HTTPX \
    --argjson naabu $RUN_NAABU \
    --argjson gau $RUN_GAU \
    --argjson gowitness $RUN_GOWITNESS \
    --argjson nuclei $RUN_NUCLEI \
    '{ "dorking": $dorking, "cloning": $cloning, "secrets": $secrets, "trivy_fs": $trivy, "endpoints": $endpoints, "subdomains_code": $subcode, "subfinder": $subfinder, "httpx": $httpx, "naabu": $naabu, "gau": $gau, "gowitness": $gowitness, "nuclei": $nuclei }')
add_to_json_summary "steps_enabled" "$skip_flags_json"


# Adjust subsequent steps based on --skip-cloning
if [[ "$RUN_CLONING" = false ]]; then
    warn "Skipping cloning (--skip-cloning). Dependent local analysis steps will also be skipped."
    RUN_SECRETS_SCAN=false; RUN_TRIVY_FS=false; RUN_ENDPOINT_EXTRACTION=false; RUN_SUBDOMAIN_EXTRACTION=false
    echo "- [Repository Cloning](#repository-cloning): Skipped (--skip-cloning)" >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "repo_cloning" '{"status": "skipped_by_flag"}'
fi

# Adjust subsequent steps based on --skip-httpx
if [[ "$RUN_HTTPX" = false ]]; then
    warn "Skipping httpx probing (--skip-httpx). Dependent steps (naabu, gau, gowitness, nuclei) will be skipped."
    RUN_NAABU=false; RUN_GAU=false; RUN_GOWITNESS=false; RUN_NUCLEI=false
    echo "- [Live Host Probing (httpx)](#live-host-probing-httpx): Skipped (--skip-httpx)" >> "$SUMMARY_REPORT_MD_FILE"
    add_to_json_summary "httpx_probing" '{"status": "skipped_by_flag"}'
fi

# Run steps based on flags
# Each function now adds its own summary entry (MD+JSON) or skip message
[[ "$RUN_DORKING" = true ]] && run_github_dorking || { echo "- [GitHub Dorking](#github-dorking): Skipped (--skip-dorking)" >> "$SUMMARY_REPORT_MD_FILE"; add_to_json_summary "github_dorking" '{"status": "skipped_by_flag"}'; }
[[ "$RUN_CLONING" = true ]] && run_repo_cloning # Handles its own skipping logic internally if listing fails

# These depend on cloning being successful (flags updated in run_repo_cloning if needed)
[[ "$RUN_SECRETS_SCAN" = true ]] && run_secrets_scanning || { echo "- [Secrets Scanning](#secrets-scanning): Skipped (--skip-secrets or cloning failed/skipped)" >> "$SUMMARY_REPORT_MD_FILE"; add_to_json_summary "secrets_scanning" '{"status": "skipped"}'; }
[[ "$RUN_TRIVY_FS" = true ]] && run_trivy_scan || { echo "- [Filesystem Scan (Trivy)](#filesystem-scan-trivy): Skipped (--skip-trivy or cloning failed/skipped)" >> "$SUMMARY_REPORT_MD_FILE"; add_to_json_summary "trivy_fs_scan" '{"status": "skipped"}'; }
[[ "$RUN_ENDPOINT_EXTRACTION" = true ]] && run_endpoint_extraction || { echo "- [JS Endpoint Extraction](#js-endpoint-extraction): Skipped (--skip-endpoints or cloning failed/skipped)" >> "$SUMMARY_REPORT_MD_FILE"; add_to_json_summary "js_endpoint_extraction" '{"status": "skipped"}'; }
[[ "$RUN_SUBDOMAIN_EXTRACTION" = true ]] && run_subdomain_extraction || { echo "- [Subdomain Extraction (Code)](#subdomain-extraction-code): Skipped (--skip-subdomains-code or cloning failed/skipped)" >> "$SUMMARY_REPORT_MD_FILE"; add_to_json_summary "subdomain_extraction_code" '{"status": "skipped"}'; }

[[ "$RUN_SUBFINDER" = true ]] && run_subfinder_enum || { echo "- [Subdomain Enumeration (Subfinder)](#subdomain-enumeration-subfinder): Skipped (--skip-subfinder)" >> "$SUMMARY_REPORT_MD_FILE"; add_to_json_summary "subfinder_enum" '{"status": "skipped_by_flag"}'; }
[[ "$RUN_HTTPX" = true ]] && run_httpx_probing # Handles its own skipping logic and updates dependent flags

# These depend on httpx running successfully (flags updated in run_httpx_probing if needed)
[[ "$RUN_NAABU" = true ]] && run_naabu_scan || { echo "- [Port Scanning (Naabu)](#port-scanning-naabu): Skipped (--skip-naabu or httpx failed/skipped)" >> "$SUMMARY_REPORT_MD_FILE"; add_to_json_summary "naabu_scan" '{"status": "skipped"}'; }
[[ "$RUN_GAU" = true ]] && run_gau_discovery || { echo "- https://medium.com/@enessyibrahim/mastering-reconnaissance-with-project-discovery-99d7a21e299a(#url-discovery-gau): Skipped (--skip-gau or httpx failed/skipped)" >> "$SUMMARY_REPORT_MD_FILE"; add_to_json_summary "gau_discovery" '{"status": "skipped"}'; }
[[ "$RUN_GOWITNESS" = true ]] && run_gowitness_screenshots || { echo "- [Screenshotting (gowitness)](#screenshotting-gowitness): Skipped (--skip-gowitness or httpx failed/skipped)" >> "$SUMMARY_REPORT_MD_FILE"; add_to_json_summary "gowitness_screenshots" '{"status": "skipped"}'; }
[[ "$RUN_NUCLEI" = true ]] && run_nuclei_scan || { echo "- [Vulnerability Scanning (Nuclei)](#vulnerability-scanning-nuclei): Skipped (--skip-nuclei or httpx failed/skipped)" >> "$SUMMARY_REPORT_MD_FILE"; add_to_json_summary "nuclei_scan" '{"status": "skipped"}'; }

[[ "$CLEANUP_REPOS" = true ]] && run_cleanup || { echo "- [Cleanup](#cleanup): Skipped (cleanup not enabled)" >> "$SUMMARY_REPORT_MD_FILE"; add_to_json_summary "cleanup" '{"status": "skipped_by_flag"}'; }

# --- Final Report ---
step "14: Finalizing Report..."
end_time=$(date +%s)
duration=$((end_time - start_time))
duration_formatted=$(date -u -d @${duration} +'%H hours %M minutes %S seconds')

echo >> "$SUMMARY_REPORT_MD_FILE" # Add newline before final sections
echo "## Final Summary" >> "$SUMMARY_REPORT_MD_FILE"
echo "**Total Execution Time:** $duration_formatted" >> "$SUMMARY_REPORT_MD_FILE"
echo "**Output Directory:** [$OUT_DIR]($OUT_DIR)" >> "$SUMMARY_REPORT_MD_FILE"
echo "**Log File:** [$LOG_FILE]($LOG_FILE)" >> "$SUMMARY_REPORT_MD_FILE"
echo "**Summary Report (MD):** [$SUMMARY_REPORT_MD_FILE]($SUMMARY_REPORT_MD_FILE)" >> "$SUMMARY_REPORT_MD_FILE"
echo "**Summary Report (JSON):** [$SUMMARY_REPORT_JSON_FILE]($SUMMARY_REPORT_JSON_FILE)" >> "$SUMMARY_REPORT_MD_FILE"

# Add final details to JSON summary
add_to_json_summary "end_time" "\"$(date -Is)\""
add_to_json_summary "total_duration_seconds" "$duration"
add_to_json_summary "total_duration_formatted" "\"$duration_formatted\""


success "GitHub Reconnaissance Script Completed for $GH_TARGET"
info "Total execution time: $duration_formatted"
info "Output saved in: $OUT_DIR"
info "Summary reports generated: $SUMMARY_REPORT_MD_FILE / $SUMMARY_REPORT_JSON_FILE"
info "Detailed log available at: $LOG_FILE"

# Display directory tree if 'tree' command is available
if check_tool "tree" "optional"; then
    info "Output Directory Structure:"
    tree -L 3 "$OUT_DIR"
fi

echo -e "${GREEN}===================== Script End ====================${NC}"
exit 0
