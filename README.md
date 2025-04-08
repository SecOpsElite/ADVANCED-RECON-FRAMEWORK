# 💥 ADVANCED RECON FRAMEWORK (ARF) — THE BUG BOUNTY HUNTER'S WEAPON OF CHOICE 🔥

<p align="center">
  <img src="https://media.tenor.com/9l3vh5cWTAkAAAAC/hacker-dark.gif" width="400">
</p>

---

## 🤖 INTRODUCTION

Welcome to the **Advanced Recon Framework (ARF)** — a powerful, stealthy, and savage reconnaissance tool crafted for **bug bounty hunters**, **ethical hackers**, and **cyber mercenaries** who want to automate deep recon like a ghost in the wire.

ARF brings together industry-favorite tools and blends them into one efficient, human-friendly machine. Every detail is crafted with a dark aesthetic and a hunter's mindset.

---

## 🔎 FEATURES

- ⚡ One-click recon automation
- ✨ Combines 15+ powerful tools
- 🔒 Finds live assets, open ports, historical data, CVEs, secrets
- 🕵️ Blackhat-grade speed and stealth
- 👀 Output organized in neat folders with HTML previews

---

## ⚡ INCLUDED MODULES & TOOLS

| Step | Feature | Tool(s) | Purpose |
|------|---------|---------|---------|
| 1 | Subdomain Enumeration | `subfinder`, `amass`, `crt.sh` | Passive/active subdomain discovery |
| 2 | Port Scanning | `naabu` | Rapid top-port detection |
| 3 | Alive Host Detection | `httpx` | Identifies live assets & technologies |
| 4 | Visual Recon | `gowitness` | Screenshots of every asset |
| 5 | Archive URLs | `gau`, `waybackurls` | Reveal past endpoints, parameters |
| 6 | WAF/CMS Detection | `wafw00f`, `httpx` | WAFs, CMS, headers, fingerprints |
| 7 | Vulnerability Scanning | `nuclei` | Runs templates for CVEs, misconfigs |
| 8 | Secret Hunting | `gitleaks`, `trufflehog` | Discover leaked keys/tokens/passwords |
| 9 | Docker/CVE Audit | `trivy` | Container analysis & security check |

---

## 🎓 HOW TO INSTALL (POINT-TO-POINT)

### ✅ STEP 1: SYSTEM REQUIREMENTS

- OS: Linux / MacOS / WSL
- Tools: `git`, `bash`, `python3`, `go`

### ✅ STEP 2: INSTALL ESSENTIALS

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install basics
sudo apt install git curl python3 python3-pip -y
```

### ✅ STEP 3: INSTALL GO

```bash
sudo apt install golang-go -y
```

### ✅ STEP 4: INSTALL RECON TOOLS

```bash
# Subfinder
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Naabu
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# HTTPX
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nuclei
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
nuclei -update-templates

# Gau
go install github.com/lc/gau/v2/cmd/gau@latest

# Gitleaks
brew install gitleaks

# TruffleHog
pip install truffleHog

# Trivy
brew install aquasecurity/trivy/trivy
```

> ⚠️ Make sure `$GOPATH/bin` is in your `$PATH`

### ✅ STEP 5: CLONE AND CONFIGURE ARF

```bash
git clone https://github.com/yourusername/advanced-recon-framework.git
cd advanced-recon-framework
chmod +x ADVANCED_RECON_FRAMEWORK.sh
```

### ✅ STEP 6: SET YOUR CONFIGURATION

Edit `config.yaml` as below:

```yaml
api_keys:
  github_token: "YOUR_TOKEN"

tool_paths:
  nuclei: nuclei
  subfinder: subfinder
  naabu: naabu
  httpx: httpx
  gau: gau
  trufflehog: trufflehog
  gitleaks: gitleaks
  trivy: trivy
  gowitness: gowitness

defaults:
  nuclei_templates: "technologies,cves,misconfiguration,vulnerabilities"
  naabu_ports: "top-100"
  httpx_threads: 50
```

---

## 🚀 HOW TO USE (LIKE A GHOST)

### ✅ BASIC EXECUTION

```bash
./ADVANCED_RECON_FRAMEWORK.sh
```

### ✅ OUTPUT STRUCTURE

```
adv_recon_results/
├── subdomains.txt
├── live_hosts.txt
├── screenshots/
├── gau.txt
├── nuclei_report.txt
├── secrets/
└── docker_cves.txt
```

All juicy details are dumped with full path tracing. Scan, screenshot, exploit-ready.

---

## 🖊️ VISUAL OUTPUT

- Live screenshots of each target
- Colored terminal output
- Vulnerabilities auto-highlighted

<p align="center">
  <img src="https://media.tenor.com/zr8LSp1qTAEAAAAd/hack.gif" width="350">
</p>

---

## 🥇 CREDITS & LOVE ✨

Created with passion by **SecOpsElite** — Cybersecurity Specialist

Follow and support:

- 🥇 [Facebook](https://www.facebook.com/secopselite)
- 🥇 [Twitter (X)](https://x.com/secopselite)
- 🥇 [Pinterest](https://www.pinterest.com/secopselite/)
- 🥇 [Instagram](https://www.instagram.com/secopselite/)

---

> "Hunt bugs. Break systems. Report responsibly."

<p align="center">
  <img src="https://media.tenor.com/JynFuzUqj6EAAAAd/anonymous-dark.gif" width="350">
</p>

