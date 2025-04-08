# <span style="color:#ff0000">⚠️</span> ADVANCED RECON FRAMEWORK <span style="color:#ff0000">⚠️</span>

<p align="center">
  <img src="https://raw.githubusercontent.com/yourname/advanced-recon-framework/main/docs/dark_banner.png" alt="Advanced Recon Framework" width="800">
</p>

[![GitHub stars](https://img.shields.io/github/stars/yourname/advanced-recon-framework?style=for-the-badge&color=red)](https://github.com/yourname/advanced-recon-framework/stargazers)
[![Forks](https://img.shields.io/github/forks/yourname/advanced-recon-framework?style=for-the-badge&color=red)](https://github.com/yourname/advanced-recon-framework/network)
[![Issues](https://img.shields.io/github/issues/yourname/advanced-recon-framework?style=for-the-badge&color=red)](https://github.com/yourname/advanced-recon-framework/issues)
[![License](https://img.shields.io/badge/License-MIT-black.svg?style=for-the-badge&color=black)](LICENSE)

<p align="center">
  <b>[ <span style="color:#ff0000">THE ULTIMATE OFFENSIVE RECONNAISSANCE PLATFORM</span> ]</b>
</p>

<p align="center">
  <i>Discover what others want to keep hidden</i>
</p>

---

## <span style="color:#ff0000">♦</span> INFILTRATION ENGINE

The **Advanced Recon Framework** is an all-in-one offensive reconnaissance platform built for elite security researchers, bug bounty hunters, and penetration testers. This framework automates and orchestrates the most powerful open-source intelligence tools into a unified kill chain that exposes critical vulnerabilities in target infrastructure with surgical precision.

> 💀 **WARNING:** This tool is NOT for the faint-hearted. Use with proper authorization ONLY. We are NOT responsible for any damage caused by improper use of this framework.

## <span style="color:#ff0000">♦</span> ARSENAL

### 🔓 Source Intelligence Module
- **GitHub Organization Mining** - Automated exfiltration of organization repositories
- **Code Analysis** - Deep detection of hardcoded secrets, credentials, and tokens
- **Sensitive Content Detection** - Pattern-based identification of sensitive data
- **Supply Chain Mapping** - Identification of dependencies and vulnerable components

### 🔓 Domain Intelligence Module
- **Subdomain Excavation** - Comprehensive subdomain enumeration and validation
- **Dormant Asset Discovery** - Detection of forgotten staging/development environments
- **Service Fingerprinting** - Identification of web technologies and server configurations
- **Port Reconnaissance** - Strategic mapping of exposed network services

### 🔓 Vulnerability Discovery Module 
- **Exposure Analysis** - Detection of exposed sensitive files and directories
- **Mass Vulnerability Scanning** - Automated detection of CVEs and security misconfigurations
- **Visual Reconnaissance** - Screenshot capture for visual inspection of web interfaces
- **Historical URL Mining** - Recovery of deleted or hidden content

## <span style="color:#ff0000">♦</span> WEAPONRY

| **Category** | **Weapons** | **Purpose** |
|--------------|-------------|-------------|
| **Source Infiltration** | <img src="https://img.shields.io/badge/-Git-F05032?style=flat-square&logo=git&logoColor=white" alt="Git"> <img src="https://img.shields.io/badge/-GitHub_CLI-181717?style=flat-square&logo=github&logoColor=white" alt="GitHub CLI"> | Repository cloning and organization enumeration |
| **Secret Extraction** | <img src="https://img.shields.io/badge/-GitLeaks-181717?style=flat-square&logo=github&logoColor=white" alt="GitLeaks"> <img src="https://img.shields.io/badge/-TruffleHog-5B4638?style=flat-square&logo=github&logoColor=white" alt="TruffleHog"> | Identification of leaked secrets and credentials |
| **Code Analysis** | <img src="https://img.shields.io/badge/-Trivy-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Trivy"> | Detection of vulnerabilities in source code and dependencies |
| **Domain Enumeration** | <img src="https://img.shields.io/badge/-Subfinder-FFB13B?style=flat-square&logoColor=white" alt="Subfinder"> | Massive subdomain discovery |
| **Service Detection** | <img src="https://img.shields.io/badge/-httpx-FF6C37?style=flat-square&logo=postman&logoColor=white" alt="httpx"> | HTTP server fingerprinting and analysis |
|  | <img src="https://img.shields.io/badge/-Naabu-000000?style=flat-square&logo=wireshark&logoColor=white" alt="Naabu"> | Advanced port scanning |
| **Content Discovery** | <img src="https://img.shields.io/badge/-gau-FF6C37?style=flat-square&logo=postman&logoColor=white" alt="gau"> | URL pattern extraction and analysis |
| **Visual Recon** | <img src="https://img.shields.io/badge/-Gowitness-000000?style=flat-square&logo=safari&logoColor=white" alt="Gowitness"> | Web interface documentation and analysis |
| **Exploit Detection** | <img src="https://img.shields.io/badge/-Nuclei-FF3E3E?style=flat-square&logo=target&logoColor=white" alt="Nuclei"> | Precision vulnerability scanning |

## <span style="color:#ff0000">♦</span> INSTALLATION

```bash
# Clone the repository
git clone https://github.com/yourname/advanced-recon-framework.git

# Enter the shadow realm
cd advanced-recon-framework

# Install dependencies
pip install -r requirements.txt

# Configure your weapons
cp config.yaml.example config.yaml
# Edit config.yaml with your preferred settings
```

## <span style="color:#ff0000">♦</span> CONFIGURATION

The framework can be customized through a powerful YAML configuration:

```yaml
# Base directory for operation outputs
base_output_directory: "./adv_recon_results"

# Custom tool paths (remove or comment to use system PATH)
tool_paths:
  gh: /usr/local/bin/gh
  git: /usr/bin/git
  gitleaks: /usr/local/bin/gitleaks
  trufflehog: /usr/local/bin/trufflehog
  subfinder: /usr/local/bin/subfinder
  httpx: /usr/local/bin/httpx
  naabu: /usr/local/bin/naabu
  gau: /usr/local/bin/gau
  gowitness: /usr/local/bin/gowitness
  nuclei: /usr/local/bin/nuclei
  trivy: /usr/local/bin/trivy

# Operational authentication
api_keys:
  github_token: ""  # Can also be set as GITHUB_TOKEN environment variable

# Module activation controls
features:
  enable_dorking: true    # GitHub code search
  enable_cloning: true    # Repository acquisition
  enable_secrets: true    # Secret scanning
  enable_trivy: true      # Code vulnerability analysis
  enable_subfinder: true  # Subdomain discovery
  enable_httpx: true      # HTTP probing
  enable_naabu: true      # Port scanning
  enable_gau: true        # URL discovery
  enable_gowitness: true  # Screenshot capture
  enable_nuclei: true     # Vulnerability scanning

# Advanced operation parameters
defaults:
  httpx_threads: 50
  naabu_ports: "top-100"
  gau_threads: 5
  gowitness_threads: 5
  nuclei_templates: "technologies,cves,vulnerabilities"
  nuclei_exclusions: "info,misc"
```

## <span style="color:#ff0000">♦</span> OPERATION

```bash
# Launch the command center
python recon_webapp.py
```

Access your command center at: http://127.0.0.1:5000/

### Mission Parameters:

1. Specify your target (GitHub organization/user)
2. Define associated domains for infrastructure reconnaissance
3. Select operational modules to execute
4. Initialize the mission and monitor real-time progress
5. Analyze comprehensive intelligence report upon mission completion

## <span style="color:#ff0000">♦</span> COMMAND CENTER

<p align="center">
  <img src="https://raw.githubusercontent.com/yourname/advanced-recon-framework/main/docs/interface_dark.png" alt="Command Interface" width="90%">
</p>

<p align="center">
  <i>The command center provides real-time mission monitoring and comprehensive intelligence reports</i>
</p>

## <span style="color:#ff0000">♦</span> INTELLIGENCE STRUCTURE

```
adv_recon_results/
├── target_XXXXXXXX/
│   ├── dorking/
│   │   └── [GitHub intelligence data]
│   ├── repos/
│   │   └── [Cloned repositories]
│   ├── secrets/
│   │   └── gitleaks_report.json
│   │   └── trufflehog_report.json
│   ├── trivy-fs/
│   │   └── trivy_fs_report.json
│   ├── endpoints/
│   │   └── gau_urls.txt
│   │   └── js_endpoints.txt
│   ├── subdomains/
│   │   └── subfinder.txt
│   │   └── code_extracted.txt
│   │   └── subdomains_combined_unique.txt
│   ├── httpx/
│   │   ├── live_hosts.txt
│   │   └── live_hosts.jsonl
│   ├── naabu/
│   │   └── naabu_results.txt
│   ├── gowitness/
│   │   ├── screenshots/
│   │   └── gowitness.sqlite3
│   ├── nuclei/
│   │   ├── nuclei_report.txt
│   │   └── nuclei_report.jsonl
│   └── final_results.json
```

## <span style="color:#ff0000">♦</span> MISSION SEQUENCE

1. **Infiltration Phase**
   - GitHub organization analysis and repository acquisition
   - Secret extraction using specialized detection algorithms
   - Comprehensive code analysis for vulnerabilities

2. **Reconnaissance Phase**
   - Subdomain enumeration using multiple techniques
   - Live host identification and service fingerprinting
   - Port scanning and exposure analysis

3. **Discovery Phase**
   - Historical URL pattern analysis
   - Visual documentation of web interfaces
   - Automated vulnerability detection and exploitation analysis

4. **Intelligence Phase**
   - Comprehensive data correlation and analysis
   - Prioritized vulnerability reporting
   - Attack surface visualization

## <span style="color:#ff0000">♦</span> PREREQUISITES

- Python 3.8+
- Flask web framework
- PyYAML library
- The following tools must be installed and accessible:
  - [GitHub CLI (gh)](https://cli.github.com/)
  - [Git](https://git-scm.com/)
  - [GitLeaks](https://github.com/zricethezav/gitleaks)
  - [TruffleHog](https://github.com/trufflesecurity/trufflehog)
  - [Subfinder](https://github.com/projectdiscovery/subfinder)
  - [httpx](https://github.com/projectdiscovery/httpx)
  - [Naabu](https://github.com/projectdiscovery/naabu)
  - [gau](https://github.com/lc/gau)
  - [Gowitness](https://github.com/sensepost/gowitness)
  - [Nuclei](https://github.com/projectdiscovery/nuclei)
  - [Trivy](https://github.com/aquasecurity/trivy)

## <span style="color:#ff0000">♦</span> FAQ

<details>
<summary><b>Is this tool legal to use?</b></summary>
This framework is designed for legitimate security research, penetration testing, and bug bounty hunting. Always ensure you have proper authorization before scanning any target organization or domain.
</details>

<details>
<summary><b>Why does this tool require so many dependencies?</b></summary>
Each integrated tool is best-in-class for its specific function. Rather than reinventing capabilities, this framework orchestrates these specialized tools into a unified reconnaissance workflow.
</details>

<details>
<summary><b>How do I get the most out of this framework?</b></summary>
For maximum effectiveness: (1) Ensure all dependencies are properly installed, (2) Configure API tokens for higher rate limits, (3) Focus on specific target scope, and (4) Review and analyze all output data.
</details>

<details>
<summary><b>Is this suitable for beginners?</b></summary>
While the web interface makes operation accessible, understanding the outputs and implications requires security background. We recommend familiarizing yourself with each individual tool first.
</details>

## <span style="color:#ff0000">♦</span> ELITE CONTRIBUTORS

Contributions that enhance the framework's capabilities are welcome. Operations protocol:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/shadow-feature`)
3. Commit your enhancements (`git commit -m 'Implement shadow feature'`)
4. Push to your branch (`git push origin feature/shadow-feature`)
5. Open a Pull Request

## <span style="color:#ff0000">♦</span> LICENSE

This project operates under the MIT License - see the [LICENSE](LICENSE) file for details.

## <span style="color:#ff0000">♦</span> ACKNOWLEDGMENTS

- The shadow architects behind the integrated open-source security tools
- The relentless bug bounty hunters and security researchers who inspire this work

---

<p align="center">
  <img src="https://raw.githubusercontent.com/yourname/advanced-recon-framework/main/docs/skull_divider.png" alt="Divider" width="300">
</p>

<p align="center">
  <i>"The quieter you become, the more you are able to hear..."</i>
</p>

<p align="center">
  <a href="https://twitter.com/your_twitter" target="_blank"><img src="https://img.shields.io/badge/Twitter-%231DA1F2.svg?&style=for-the-badge&logo=twitter&logoColor=white" alt="Twitter"></a>
  <a href="https://github.com/your_github" target="_blank"><img src="https://img.shields.io/badge/GitHub-%23181717.svg?&style=for-the-badge&logo=github&logoColor=white" alt="GitHub"></a>
  <a href="https://discord.gg/your_discord" target="_blank"><img src="https://img.shields.io/badge/Discord-%237289DA.svg?&style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
</p>
