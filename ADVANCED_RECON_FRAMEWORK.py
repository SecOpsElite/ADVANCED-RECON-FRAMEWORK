import Flask
import PyYAML # Requires pip install PyYAML
import subprocess
import threading
import os
import json
import shlex
import uuid
import datetime
from pathlib import Path

# --- Flask App Setup ---
app = Flask(__name__)
# IMPORTANT: Change this to a strong random secret key in a real deployment
app.secret_key = os.urandom(32) 

# --- Global Configuration ---
CONFIG = {}
BASE_OUTPUT_DIR = "./adv_recon_results" # Default, overridden by config
TOOL_PATHS = {} # Store tool paths from config
SCAN_STATUS = {} # Dictionary to track status of running/completed scans: {scan_id: {"status": "running/completed/failed", "output_dir": ..., "log": [...]}}

# --- Helper Functions ---

def load_config(config_path="config.yaml"):
    """Loads configuration from YAML file."""
    global CONFIG, BASE_OUTPUT_DIR, TOOL_PATHS
    try:
        with open(config_path, 'r') as f:
            CONFIG = yaml.safe_load(f)
        BASE_OUTPUT_DIR = CONFIG.get('base_output_directory', BASE_OUTPUT_DIR)
        TOOL_PATHS = CONFIG.get('tool_paths', {})
        # Load API keys from config, but prioritize environment variables
        gh_token_conf = CONFIG.get('api_keys', {}).get('github_token')
        os.environ['GITHUB_TOKEN'] = os.environ.get('GITHUB_TOKEN', gh_token_conf or "")
        if not os.environ.get('GITHUB_TOKEN'):
             print("[WARN] GITHUB_TOKEN not found in environment or config.yaml. Rate limits may apply.")
        else:
             print("[INFO] GITHUB_TOKEN is set.")
        print(f"[INFO] Loaded configuration from {config_path}")
        print(f"[INFO] Base output directory set to: {BASE_OUTPUT_DIR}")
    except FileNotFoundError:
        print(f"[ERROR] Configuration file '{config_path}' not found. Using defaults.")
        # Set default tool paths assuming they are in PATH
        TOOL_PATHS = {
            'gh': 'gh', 'git': 'git', 'gitleaks': 'gitleaks', 'trufflehog': 'trufflehog',
            'subfinder': 'subfinder', 'httpx': 'httpx', 'naabu': 'naabu', 'gau': 'gau',
            'gowitness': 'gowitness', 'nuclei': 'nuclei', 'trivy': 'trivy'
        }
    except Exception as e:
        print(f"[ERROR] Failed to load or parse configuration '{config_path}': {e}")
        exit(1)

def get_tool_path(tool_name):
    """Gets the executable path for a tool from config or assumes it's in PATH."""
    return TOOL_PATHS.get(tool_name, tool_name) # Default to tool name itself

def log_scan_message(scan_id, level, message):
    """Logs messages for a specific scan."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] [{level.upper()}] {message}"
    print(f"Scan {scan_id}: {log_entry}") # Also print to console
    if scan_id in SCAN_STATUS:
        SCAN_STATUS[scan_id].setdefault("log", []).append(log_entry)
        # Limit log size in memory (optional)
        if len(SCAN_STATUS[scan_id]["log"]) > 500:
            SCAN_STATUS[scan_id]["log"].pop(0)

def run_command(scan_id, command_list, cwd=None, log_output=True):
    """Runs a command using subprocess, logs output, and returns exit code."""
    command_str = ' '.join(shlex.quote(str(arg)) for arg in command_list)
    log_scan_message(scan_id, "info", f"Running command: {command_str}" + (f" in {cwd}" if cwd else ""))
    
    try:
        process = subprocess.Popen(
            command_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=cwd
        )
        
        # Log output line by line
        if log_output and process.stdout:
             for line in iter(process.stdout.readline, ''):
                 if line: # Avoid logging empty lines
                    log_scan_message(scan_id, "cmd_out", line.strip())
        
        process.wait() # Wait for completion
        log_scan_message(scan_id, "info", f"Command finished with exit code {process.returncode}.")
        return process.returncode
    except FileNotFoundError:
        log_scan_message(scan_id, "error", f"Command not found: {command_list[0]}. Check tool path in config.yaml or system PATH.")
        return -1 # Indicate file not found error
    except Exception as e:
        log_scan_message(scan_id, "error", f"Failed to run command '{command_str}': {e}")
        return -2 # Indicate other exception

# --- Reconnaissance Workflow Function (runs in background thread) ---

def execute_recon_workflow(scan_id, options):
    """The main function performing the reconnaissance steps."""
    target = options['target']
    output_dir = options['output_dir']
    domains = options['domains']
    
    # Create output directory structure
    dirs = {
        "base": Path(output_dir),
        "dorking": Path(output_dir) / "dorking",
        "repos": Path(output_dir) / "repos",
        "secrets": Path(output_dir) / "secrets",
        "trivy": Path(output_dir) / "trivy-fs",
        "endpoints": Path(output_dir) / "endpoints",
        "subdomains": Path(output_dir) / "subdomains",
        "httpx": Path(output_dir) / "httpx",
        "naabu": Path(output_dir) / "naabu",
        "gowitness": Path(output_dir) / "gowitness",
        "nuclei": Path(output_dir) / "nuclei",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
        
    results = {"scan_id": scan_id, "target": target, "options": options, "findings": {}}
    log_scan_message(scan_id, "info", f"Starting reconnaissance workflow for target: {target}")
    SCAN_STATUS[scan_id]["status"] = "running"

    try:
        # --- Step 1: GitHub Dorking ---
        if options.get('run_dorking', False):
            log_scan_message(scan_id, "step", "Running GitHub Dorking...")
            # Simplified dorking example - needs expansion based on Bash script logic
            dork_cmd = [get_tool_path('gh'), 'search', 'code', f'org:{target} filename:.env', '--limit', '5', '--json', 'url,path,repository']
            exit_code = run_command(scan_id, dork_cmd)
            results["findings"]["dorking_status"] = "completed" if exit_code == 0 else "failed"
            # TODO: Capture and parse dorking output

        # --- Step 2: Cloning ---
        cloned_successfully = False
        if options.get('run_cloning', False):
            log_scan_message(scan_id, "step", "Cloning repositories...")
            # Simplified cloning - needs repo listing and looping from Bash script logic
            repo_url = f"https://github.com/{target}/{target}.git" # Example repo - needs actual listing
            clone_dir = dirs["repos"] / target # Example clone dir
            clone_cmd = [get_tool_path('git'), 'clone']
            if not options.get('full_clone'):
                clone_cmd.extend(['--depth', '1'])
            clone_cmd.extend([repo_url, str(clone_dir)])
            exit_code = run_command(scan_id, clone_cmd)
            if exit_code == 0:
                cloned_successfully = True
            results["findings"]["cloning_status"] = "completed" if cloned_successfully else "failed/skipped"
            # TODO: Implement gh repo list and loop for multiple repos

        # --- Steps depending on cloning ---
        if cloned_successfully:
            # --- Step 3: Secrets Scan ---
            if options.get('run_secrets', False):
                log_scan_message(scan_id, "step", "Running Secrets Scanning...")
                gitleaks_cmd = [get_tool_path('gitleaks'), 'detect', '-s', str(dirs["repos"]), '--report-path', str(dirs["secrets"] / "gitleaks_report.json"), '-f', 'json', '--no-banner', '-v']
                run_command(scan_id, gitleaks_cmd)
                # TODO: Add TruffleHog command, parse reports for findings count

            # --- Step 4: Trivy FS Scan ---
            if options.get('run_trivy', False):
                 log_scan_message(scan_id, "step", "Running Trivy Filesystem Scan...")
                 trivy_report = dirs["trivy"] / "trivy_fs_report.json"
                 trivy_cmd = [get_tool_path('trivy'), 'fs', '--format', 'json', '--output', str(trivy_report), '--ignore-unfixed', '--severity', 'MEDIUM,HIGH,CRITICAL', str(dirs["repos"])]
                 run_command(scan_id, trivy_cmd)
                 # TODO: Parse report for findings count

            # TODO: Implement JS Endpoint Extraction (find + grep/cat)
            # TODO: Implement Subdomain Extraction from Code (grep)
        else:
             log_scan_message(scan_id, "warn", "Skipping local analysis steps as cloning failed or was skipped.")


        # --- Step 7: Subfinder ---
        subfinder_output = dirs["subdomains"] / "subfinder.txt"
        if options.get('run_subfinder', False) and domains:
            log_scan_message(scan_id, "step", "Running Subfinder...")
            domain_list_file = dirs["subdomains"] / "domains.tmp"
            with open(domain_list_file, 'w') as f:
                for d in domains:
                    f.write(f"{d}\n")
            subfinder_cmd = [get_tool_path('subfinder'), '-dL', str(domain_list_file), '-o', str(subfinder_output), '-silent']
            run_command(scan_id, subfinder_cmd)
            domain_list_file.unlink(missing_ok=True) # Clean up temp file
        else:
            subfinder_output.touch() # Create empty file if skipped

        # TODO: Combine subdomains from code and subfinder into a single list file

        # --- Step 8: httpx ---
        httpx_output_text = dirs["httpx"] / "live_hosts.txt"
        httpx_output_json = dirs["httpx"] / "live_hosts.jsonl"
        httpx_input_file = dirs["subdomains"] / "subdomains_combined_unique.txt" # Assumes this file is created
        live_hosts_found = False
        if options.get('run_httpx', False) and httpx_input_file.exists() and httpx_input_file.stat().st_size > 0:
             log_scan_message(scan_id, "step", "Running httpx probing...")
             httpx_cmd = [
                 get_tool_path('httpx'), '-silent', '-l', str(httpx_input_file),
                 '-o', str(httpx_output_text), '-json', '-o', str(httpx_output_json),
                 '-status-code', '-title', '-tech-detect',
                 '-threads', str(CONFIG.get('defaults', {}).get('httpx_threads', 50))
             ]
             exit_code = run_command(scan_id, httpx_cmd)
             if exit_code == 0 and httpx_output_text.exists() and httpx_output_text.stat().st_size > 0:
                 live_hosts_found = True
        else:
             log_scan_message(scan_id, "warn", "Skipping httpx as input file is missing/empty or step is disabled.")
             httpx_output_text.touch() # Create empty file

        # --- Steps depending on httpx ---
        if live_hosts_found:
            # --- Step 9: Naabu ---
            if options.get('run_naabu', False):
                log_scan_message(scan_id, "step", "Running Naabu port scanning...")
                naabu_output = dirs["naabu"] / "naabu_results.txt"
                naabu_cmd = [
                    get_tool_path('naabu'), '-list', str(httpx_output_text), # Input is httpx text output
                    '-top-ports', str(CONFIG.get('defaults', {}).get('naabu_ports', 'top-100')),
                    '-silent', '-o', str(naabu_output)
                ]
                run_command(scan_id, naabu_cmd)

            # --- Step 10: gau ---
            if options.get('run_gau', False):
                log_scan_message(scan_id, "step", "Running gau URL discovery...")
                gau_output = dirs["endpoints"] / "gau_urls.txt"
                # Pipe httpx output to gau (requires careful handling or temp file)
                # Simplified: run gau on the input domain list for now
                if domains:
                    domain_list_file_gau = dirs["endpoints"] / "domains_gau.tmp"
                    with open(domain_list_file_gau, 'w') as f:
                        for d in domains: f.write(f"{d}\n")
                    # Using cat | gau structure
                    cat_cmd = [ 'cat', str(domain_list_file_gau) ]
                    gau_cmd = [ get_tool_path('gau'), '--threads', str(CONFIG.get('defaults', {}).get('gau_threads', 5)), '--subs' ]
                    
                    log_scan_message(scan_id, "info", f"Running command: cat {shlex.quote(str(domain_list_file_gau))} | {' '.join(shlex.quote(arg) for arg in gau_cmd)}")
                    try:
                        with open(gau_output, 'w') as f_out:
                            ps_cat = subprocess.Popen(cat_cmd, stdout=subprocess.PIPE)
                            ps_gau = subprocess.Popen(gau_cmd, stdin=ps_cat.stdout, stdout=f_out, stderr=subprocess.PIPE, text=True)
                            ps_cat.stdout.close() # Allow ps_cat to receive a SIGPIPE if ps_gau exits.
                            stderr_output = ps_gau.communicate()[1]
                            if stderr_output: log_scan_message(scan_id, "cmd_out", f"gau stderr: {stderr_output.strip()}")
                            log_scan_message(scan_id, "info", f"gau finished with exit code {ps_gau.returncode}.")
                    except Exception as e:
                         log_scan_message(scan_id, "error", f"Failed to run gau pipeline: {e}")
                    domain_list_file_gau.unlink(missing_ok=True)
                else:
                     log_scan_message(scan_id, "warn", "Skipping gau as no domains were provided.")


            # --- Step 11: gowitness ---
            if options.get('run_gowitness', False):
                 log_scan_message(scan_id, "step", "Running gowitness screenshotting...")
                 gowitness_cmd = [
                     get_tool_path('gowitness'), 'file', '-f', str(httpx_output_text), # Input httpx text output
                     '--destination', str(dirs["gowitness"] / "screenshots/"),
                     '--db-path', str(dirs["gowitness"] / "gowitness.sqlite3"),
                     '--threads', str(CONFIG.get('defaults', {}).get('gowitness_threads', 5))
                 ]
                 run_command(scan_id, gowitness_cmd)

            # --- Step 12: Nuclei ---
            if options.get('run_nuclei', False):
                log_scan_message(scan_id, "step", "Running Nuclei vulnerability scanning...")
                nuclei_output_txt = dirs["nuclei"] / "nuclei_report.txt"
                nuclei_output_json = dirs["nuclei"] / "nuclei_report.jsonl"
                nuclei_cmd = [
                    get_tool_path('nuclei'), '-l', str(httpx_output_text),
                    '-t', str(CONFIG.get('defaults', {}).get('nuclei_templates', 'technologies,cves')),
                    '-etags', str(CONFIG.get('defaults', {}).get('nuclei_exclusions', 'info,misc')),
                    '-stats', '-silent',
                    '-o', str(nuclei_output_txt),
                    '-jsonl', '-o', str(nuclei_output_json)
                ]
                run_command(scan_id, nuclei_cmd)
                # TODO: Parse nuclei JSON output for findings count/summary

        else:
             log_scan_message(scan_id, "warn", "Skipping Naabu, Gau, Gowitness, Nuclei as no live hosts were found or httpx was skipped.")


        # --- Step 13: Cleanup ---
        if options.get('cleanup', False):
             log_scan_message(scan_id, "step", "Running cleanup...")
             cleanup_cmd = ['rm', '-rf', str(dirs["repos"])]
             run_command(scan_id, cleanup_cmd)


        SCAN_STATUS[scan_id]["status"] = "completed"
        log_scan_message(scan_id, "success", "Reconnaissance workflow completed.")

    except Exception as e:
        log_scan_message(scan_id, "error", f"Workflow failed with unexpected error: {e}")
        SCAN_STATUS[scan_id]["status"] = "failed"
        SCAN_STATUS[scan_id]["error_message"] = str(e)

    # --- Save final results ---
    results_file = dirs["base"] / "final_results.json"
    results["end_time"] = datetime.datetime.now().isoformat()
    results["status"] = SCAN_STATUS[scan_id]["status"]
    if SCAN_STATUS[scan_id]["status"] == "failed":
         results["error_message"] = SCAN_STATUS[scan_id].get("error_message", "Unknown error")
    try:
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=4)
        log_scan_message(scan_id, "info", f"Final results saved to {results_file}")
    except Exception as e:
        log_scan_message(scan_id, "error", f"Failed to save final results JSON: {e}")


# --- Flask Routes ---

@app.route('/', methods=['GET'])
def index():
    """Serves the main input form."""
    # Pass available skip flags and config defaults to the template
    skip_flags = [k.replace('enable_', '') for k, v in CONFIG.get('features', {}).items() if v and k.startswith('enable_')]
    default_nuclei_templates = CONFIG.get('defaults', {}).get('nuclei_templates', '')
    return render_template('index.html', skip_flags=skip_flags, default_nuclei_templates=default_nuclei_templates)

@app.route('/run', methods=['POST'])
def run_scan_route():
    """Handles form submission and starts the scan."""
    scan_id = str(uuid.uuid4()) # Generate unique ID for this scan
    options = {
        'scan_id': scan_id,
        'target': request.form.get('target', '').strip(),
        'output_dir': request.form.get('output_dir', '').strip(),
        'domains': [d.strip() for d in request.form.get('domains', '').split(',') if d.strip()],
        'full_clone': request.form.get('full_clone') == 'true',
        'cleanup': request.form.get('cleanup') == 'true',
        'start_time': datetime.datetime.now().isoformat()
    }

    if not options['target']:
        flash('GitHub Target is required.', 'error')
        return redirect(url_for('index'))

    if not options['output_dir']:
        options['output_dir'] = str(Path(BASE_OUTPUT_DIR) / options['target'].replace('/', '_') + "_" + scan_id[:8])

    # Determine which steps to run based on checkboxes and config features
    features = CONFIG.get('features', {})
    for feature_flag, default_enabled in features.items():
         if feature_flag.startswith('enable_'):
             step_name = feature_flag.replace('enable_', '')
             # Run if feature is enabled in config AND not skipped in UI
             options[f'run_{step_name}'] = default_enabled and (request.form.get(f'skip_{step_name}') is None)

    # Initialize status
    SCAN_STATUS[scan_id] = {
        "status": "starting",
        "output_dir": options['output_dir'],
        "target": options['target'],
        "start_time": options['start_time'],
        "log": []
    }

    # Run the workflow in a background thread
    thread = threading.Thread(target=execute_recon_workflow, args=(scan_id, options), daemon=True)
    thread.start()

    flash(f'Scan started successfully! Scan ID: {scan_id}. Results will be available soon.', 'success')
    # Redirect to a status/results page for this scan
    return redirect(url_for('scan_status', scan_id=scan_id))

@app.route('/status/<scan_id>')
def scan_status(scan_id):
    """Displays the status and results of a specific scan."""
    status_info = SCAN_STATUS.get(scan_id)
    if not status_info:
        return "Scan ID not found.", 404

    # Try to load final results if completed
    results_data = None
    results_file = Path(status_info.get("output_dir", "")) / "final_results.json"
    if status_info["status"] == "completed" or status_info["status"] == "failed":
         if results_file.exists():
             try:
                 with open(results_file, 'r') as f:
                     results_data = json.load(f)
             except Exception as e:
                 log_scan_message(scan_id, "error", f"Failed to load results file {results_file}: {e}")
                 status_info["error_message"] = f"Failed to load results file: {e}"


    return render_template('results.html', scan_id=scan_id, status_info=status_info, results_data=results_data)

@app.route('/status')
def all_scans():
     """Lists all tracked scans."""
     return render_template('all_scans.html', scans=SCAN_STATUS)


# --- Main Execution ---
if __name__ == '__main__':
    load_config() # Load config on startup
    print("Starting Advanced Recon Flask server on http://127.0.0.1:5000")
    print(f"Ensure required tools are installed and accessible via config or PATH.")
    print(f"Base output directory: {BASE_OUTPUT_DIR}")
    app.run(debug=True, host='127.0.0.1', port=5000) # Use threaded=True for multiple background scans if needed
