<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/origindive_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="images/origindive_light.png">
  <img alt="origindive ascii title" src="images/origindive_light.png">
</picture>

# origindive

**Dive deep to discover origin servers** - A powerful security analysis tool for discovering real origin server IPs hidden behind CDN/WAF services through both passive reconnaissance and active scanning.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.23+-blue.svg)](https://golang.org/)
[![Release](https://img.shields.io/github/v/release/jhaxce/origindive)](https://github.com/jhaxce/origindive/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/jhaxce/origindive)](https://goreportcard.com/report/github.com/jhaxce/origindive)
[![codecov](https://codecov.io/gh/jhaxce/origindive/branch/main/graph/badge.svg)](https://codecov.io/gh/jhaxce/origindive)
[![Go Reference](https://pkg.go.dev/badge/github.com/jhaxce/origindive.svg)](https://pkg.go.dev/github.com/jhaxce/origindive)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fjhaxce%2Forigindive.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fjhaxce%2Forigindive?ref=badge_shield)
</div>

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [User Agent Customization](#user-agent-customization)
- [Proxy Support](#proxy-support)
- [WAF Filtering](#waf-filtering)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Migration from v2.x](#migration-from-v2x)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

**origindive** helps security researchers and penetration testers discover the real IP addresses of web servers that are protected by Content Delivery Networks (CDN) or Web Application Firewalls (WAF). 

### Key Capabilities

- **Active Scanning**: Test IP ranges with custom Host headers to identify origin servers
- **WAF Filtering**: Automatically skip known CDN/WAF IP ranges (Cloudflare, AWS, Fastly, Akamai, etc.)
- **Passive Reconnaissance**: Discover potential IPs through OSINT sources (coming soon)
- **Multi-Format Output**: Export results as text, JSON, or CSV

### How It Works

When a website uses a CDN like Cloudflare:
1. DNS points to the CDN's IP addresses  
2. The CDN forwards requests to the origin server
3. The origin server often has a different, hidden IP address

origindive sends HTTP requests directly to IP addresses with your target domain in the Host header. If the server responds with a 200 OK, it's likely the real origin server.

## ✨ Features

### v3.2 New Features

- **🔗 Smart Redirect Following** - Follow HTTP redirects while preserving IP testing
  - Flexible syntax: `--follow-redirect` (default 10) or `--follow-redirect=5` (custom max)
  - IP-preserving redirects: Test same IP through entire redirect chain
  - Full chain tracking: Records complete path (301 → HTTPS → final destination)
  - Inline display: Redirect chains shown with each 200 OK result
  
- **⚠️ False Positive Detection** - Identify shared hosting via Host header validation
  - Post-scan validation: Re-tests successful IPs WITHOUT Host header
  - Detects behavior differences: Flags IPs that redirect differently
  - Smart comparison: Ignores HTTP→HTTPS upgrades, catches real mismatches  
  - Automatic warnings: Appends ⚠️ to redirect chains for suspicious IPs
  - Summary integration: Shows verified origins separately from all 200 OK
  
- **📊 Enhanced Summary Display** - Clear distinction between real and potential false positives
  - `[+] Found: 203.0.113.10` - Verified origins (no warnings)
  - `[+] 200 OK: 6 (...)` - All responses including potential false positives
  - Smart filtering: Only shows verified line if real origins found

**Example Output with Validation**:
```
[+] 203.0.113.10 --> 200 OK (1.4s) | "Example Site" [dda7f97c]
    Redirect chain:
      1. 301 http://203.0.113.10 -> https://example.com:443/

[+] 203.0.113.20 --> 200 OK (545ms) [05c4b0d2]
    Redirect chain:
      1. 301 http://203.0.113.20 -> https://example.com:443/
      2. ⚠ Without Host header: https://203.0.113.20:443/ (different from https://example.com:443/)

═══════════════════════════════════════════════════════════════
Scan Results Summary
═══════════════════════════════════════════════════════════════
[+] Found: 203.0.113.10
[+] 200 OK: 6 (203.0.113.15, 203.0.113.20, 203.0.113.25, 203.0.113.30, 203.0.113.35, 203.0.113.10)
[*] Total Scanned: 27
[T] Duration: 12.39s
[R] Scan Rate: 2.18 IPs/s
═══════════════════════════════════════════════════════════════
```

### v3.1 Features

- **🌍 Country-Aware Proxy Fetching** - Auto-detect your location for geo-optimized proxies
  - Detects country from Cloudflare CDN trace (loc=XX)
  - Fetches country-specific proxies from ProxyScrape and GeoNode
  - 74% fewer proxies to validate (675 → 174 for PH users)
  - 3x better quality (1.90% → 5.75% working proxies)
  - Lower latency with geo-local proxies
  - GeoNode 90% uptime filter for reliability

- **⭐ Webshare.io Premium Proxy Integration** - Professional proxy service support
  - Fetch proxies from Webshare.io API (requires subscription)
  - Automatic authentication with API token
  - Premium proxies prioritized in validation (placed first)
  - Global configuration support in `~/.config/origindive/config.yaml`
  - 10+ datacenter proxies across US, GB, JP, PL, ES
  
- **📡 Multi-Endpoint Proxy Validation** - Robust validation with 6 fallback services
  - Primary: api.ipify.org (fast, plain IP)
  - Secondary: AWS checkip, icanhazip.com, Webshare.io IPv4
  - Fallback: checkip.dyndns.org, Cloudflare CDN trace
  - Intelligent response parsing (plain, HTML, key-value formats)
  - Sequential fallback for maximum reliability

- **🚀 Smart Proxy Sampling** - Intelligent validation for large lists
  - First 50 proxies always validated (guarantees premium inclusion)
  - 20% random sampling (max 2,000) for remaining proxies
  - 50 parallel workers (5x faster than v3.0)
  - 60-second timeout with early exit
  - Prevents premium proxies from getting lost

### v3.0 Features

- **⭐ WAF/CDN IP Filtering** - Automatically skip 108+ known CDN/WAF ranges
  - Saves massive time by filtering Cloudflare, AWS CloudFront, Fastly, Akamai, Incapsula, Sucuri
  - Auto-updates from official provider APIs
  - Custom WAF ranges support (JSON or plain text)
  - Per-provider statistics
  
- **📁 Flexible Input** - Multiple ways to specify targets
  - Single IP ranges (`-s start -e end`)
  - CIDR notation (`-n 192.168.1.0/24`)
  - Input files with mixed formats (IPs, CIDRs, ranges)
  - Comments and blank lines supported in files
  
- **⚙️ YAML Configuration** - Save your scan preferences
  - Load settings from config file (`--config config.yaml`)
  - CLI flags override config file values
  - Shareable configs across team
  
- **🔄 Self-Update** - Stay up to date effortlessly
  - Check and install latest release (`--update`)
  - Downloads from GitHub releases
  - Automatic binary replacement
  
- **Modular Architecture** - Clean, maintainable codebase
  - Separated packages for core, scanner, WAF, IP utilities, output
  - Easy to extend and customize
  
- **Enhanced Output** - Multiple export formats
  - Colored text output
  - JSON for programmatic use
  - CSV for spreadsheets

### Core Features

- ✅ Multi-threaded IP range scanning with configurable workers
- ✅ CIDR notation support (`192.168.1.0/24`)
- ✅ Input file support (mixed IPs, CIDRs, and ranges)
- ✅ Custom WAF ranges (JSON or text format)
- ✅ Real-time progress bar with ETA
- ✅ Custom HTTP headers and methods
- ✅ Configurable timeouts
- ✅ Private/reserved IP detection
- ✅ Cross-platform (Windows, Linux, macOS)
- ✅ Auto-update functionality

## 🚀 Installation

### Prerequisites
- Go 1.23 or higher

### Download Pre-built Binary

Download the latest release for your platform:

```bash
# Linux/macOS
curl -L https://github.com/jhaxce/origindive/releases/latest/download/origindive-linux-amd64.tar.gz | tar xz
sudo mv origindive /usr/local/bin/

# Or download from releases page
# https://github.com/jhaxce/origindive/releases
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/jhaxce/origindive.git
cd origindive

# Build
go build -o origindive cmd/origindive/main.go

# Install system-wide (optional)
sudo mv origindive /usr/local/bin/

# Windows
# Move origindive.exe to a directory in your PATH
```

### Install with Go

```bash
go install github.com/jhaxce/origindive/cmd/origindive@latest

# The binary will be in $GOPATH/bin or ~/go/bin
```

## 🏃 Quick Start

```bash
# Auto-scan mode: Passive reconnaissance + active scanning
origindive -d example.com

# Passive-only mode: Discover IPs without active scanning
origindive -d example.com --passive -o discovered_ips.txt

# Active scan on discovered IPs from passive scan (auto mode)
origindive -d example.com --auto-scan

# Basic IP range scan
origindive -d example.com -s 192.168.1.1 -e 192.168.1.254

# CIDR subnet with redirect following
origindive -d example.com -n 192.168.1.0/24 --follow-redirect

# Scan with redirect validation and false positive detection
origindive -d example.com -i ips.txt --follow-redirect=5

# Scan ASN with verification and redirect following
origindive -d example.com --asn AS4775 --skip-waf --follow-redirect --verify

# Scan with WAF filtering enabled
origindive -d example.com -n 23.0.0.0/16 --skip-waf -j 20

# Scan IPs from a file
origindive -d example.com -i ips.txt --skip-waf

# Scrape a file for IPs and use them as input
origindive -d example.com --input-scrape eulap-ips.json

# Use random browser user agent
origindive -d example.com -n 192.168.1.0/24 -A random

# Use proxy for scanning
origindive -d example.com -i targets.txt -P http://1.2.3.4:8080

# Auto-fetch and use public proxies
origindive -d example.com -i targets.txt --proxy-auto --proxy-rotate

# Scan ASN (active scan only, no passive)
origindive -d example.com --asn AS4775 --skip-waf

# Use configuration file
origindive --config config.yaml

# Check for updates
origindive --update
```

## 📖 Usage

### Scan Modes

origindive supports three scanning modes:

#### 1. Auto-Scan Mode (Default when only domain provided)
Automatically runs passive reconnaissance first, then performs active scanning on discovered IPs:

```bash
# Discover IPs via passive sources, then scan them
origindive -d example.com

# Auto-scan with custom settings
origindive -d example.com -j 20 -t 3
```

**Workflow:**
1. Query Certificate Transparency logs for subdomains
2. Check DNS history for the domain
3. Query Shodan/Censys (if API keys configured)
4. Collect discovered IPs
5. Perform active HTTP scanning on all discovered IPs

#### 2. Passive-Only Mode
Discover IPs without active scanning:

```bash
# Save discovered IPs to file
origindive -d example.com --passive -o discovered_ips.txt

# Passive scan with specific sources
origindive -d example.com --passive --passive-sources ct,dns,shodan
```

**Output:** List of IPs discovered from OSINT sources (no HTTP requests sent)

#### 3. Active-Only Mode
Direct active scanning on specified IP ranges (no passive reconnaissance):

```bash
# Scan specific CIDR
origindive -d example.com -n 192.168.1.0/24

# Scan IP range
origindive -d example.com -s 192.168.1.1 -e 192.168.1.254

# Scan ASN (Autonomous System Number) - Active scan only
origindive -d example.com --asn AS4775
origindive -d example.com --asn 9299  # AS prefix optional

# Scan multiple ASNs (comma-separated) - Active scan only
origindive -d example.com --asn AS4775,AS9299,AS10139
origindive -d example.com --asn 4775,9299  # Mixed formats work too

# Scan from file
origindive -d example.com -i targets.txt
```

**ASN Lookup Feature (Active Scan Only):**
- Automatically fetches IP ranges from [ipapi.is](https://ipapi.is)
- Performs direct active HTTP scanning (no passive reconnaissance)
- Caches results permanently in `~/.cache/origindive/asn/`
- Supports both `AS4775` and `4775` formats
- Find ASN codes at [whois.ipinsight.io/countries](https://whois.ipinsight.io/countries)
- See [docs/ASN_LOOKUP.md](docs/ASN_LOOKUP.md) for details

### Basic Usage

```bash
# Scan IP range
origindive -d example.com -s 23.192.228.1 -e 23.192.228.254

# Scan CIDR
origindive -d example.com -n 23.192.228.0/24

# Scan ASN ranges with WAF filtering
origindive -d example.com --asn AS18233 --skip-waf -j 30

# Scan multiple ASNs at once
origindive -d example.com --asn AS4775,AS9299,AS17639 --skip-waf

# Verify responses (extract title and hash to identify unique servers)
origindive -d example.com --asn AS18233 --skip-waf --verify

# Scan from file (supports IPs, CIDRs, ranges, comments)
origindive -d example.com -i targets.txt

# Use YAML config file
origindive --config myconfig.yaml
```

### Input File Format

The `-i/--input` flag accepts files with mixed IP formats:

```text
# Single IPs
192.0.2.1
198.51.100.5

# CIDR notation
192.0.2.0/24
198.51.100.0/24

# IP ranges
192.0.2.1-192.0.2.254

# Comments and blank lines are ignored
```

### Configuration File

Create a `config.yaml` file (see `configs/example.yaml`):

```yaml
domain: "example.com"
cidr: "192.168.1.0/24"
skip_waf: true
workers: 20
timeout: "10s"
format: "json"
output_file: "results.json"
```

Then run:

```bash
origindive --config config.yaml

# Override config file settings with CLI flags
origindive --config config.yaml -d different.com -j 50
```

### Self-Update

```bash
# Check for and install latest release
origindive --update
```

### Active Scanning

#### IP Range Mode
```bash
# Scan from start to end IP
origindive -d example.com -s 23.192.228.1 -e 23.192.228.254
```

#### CIDR Mode
```bash
# Scan a /24 subnet using -n (smart detection)
origindive -d example.com -n 23.192.228.0/24

# Or use -c explicitly
origindive -d example.com -c 23.192.228.0/24

# Larger subnet with more workers
origindive -d example.com -n 10.0.0.0/16 -j 50
```

**Note**: The `-n` flag smartly detects if you provide:
- Full CIDR (e.g., `-n 192.168.1.0/24`) → Active mode
- Just mask (e.g., `-n /24`) → Passive mode (expands discovered IPs)

#### Input File Mode
```bash
# File with IPs and CIDRs
origindive -d example.com -i targets.txt -j 20

# Apply /24 mask to single IPs in file
origindive -d example.com -i ips.txt -n /24
```

**targets.txt example:**
```
# Example IP ranges
192.0.2.0/24
198.51.100.0/24

# Single IPs
203.0.113.10
203.0.113.20

# Comments are ignored
```

### Common Flags

```
Target:
  -d, --domain string       Target domain (required)
  
IP Range (choose one):
  -s, --start-ip string     Start IP address
  -e, --end-ip string       End IP address
  -n, --expand-netmask str  CIDR (e.g., 192.168.1.0/24) OR mask for passive (/24)
  -c, --cidr string         CIDR notation (e.g., 192.168.0.0/24)
  -i, --input string        Input file with IPs/CIDRs/ranges
  --input-scrape string    Scrape IPs from a file (writes `<domain>-ips.txt` and uses it as input)
  --asn string              ASN lookup, comma-separated (e.g., AS4775,AS9299)
  
Configuration:
  --config string           Load settings from YAML file
  --update                  Check and install latest version
  
Performance:
  -j, --threads int         Parallel workers (default: 10)
  -t, --timeout int         HTTP timeout in seconds (default: 5)
  --connect-timeout int     TCP connect timeout in seconds (default: 3)
  
WAF Filtering:
  --skip-waf                Skip all known WAF/CDN IPs
  --skip-providers string   Skip specific providers (comma-separated)
  --custom-waf string       Custom WAF ranges file (JSON or text)
  --show-skipped            Display skipped IPs
  --no-waf-update           Disable WAF database auto-update
  
Output:
  -o, --output string       Save results to file
  -f, --format string       Output format: text|json|csv (default: text)
  -q, --quiet               Minimal output
  -a, --show-all            Show all responses (not just 200 OK)
  --no-color                Disable colored output
  --no-progress             Disable progress bar
  
HTTP:
  -m, --method string       HTTP method (default: GET)
  -H, --header string       Custom header (format: "Name: value")
  -A, --user-agent string   User-Agent: random, chrome, firefox, safari, edge, opera, brave, mobile, or custom string
  --no-ua                   Disable User-Agent header
  --verify                  Extract title and hash response body for verification
  --filter-unique           Show only IPs with unique content (requires --verify)
  --follow-redirect[=N]     Follow redirects (default max: 10, custom: N)
  
Proxy:
  -P, --proxy string        Proxy URL (http://IP:PORT or socks5://IP:PORT)
  --proxy-auto              Auto-fetch proxies from public lists
  --proxy-rotate            Rotate through proxy list for each request
  --proxy-test              Test proxy before use (default: true)
  
Passive Mode:
  --passive                 Passive reconnaissance only (no active scanning)
  --auto-scan               Auto-scan: passive reconnaissance then active scanning
  --passive-sources string  Comma-separated passive sources (ct,dns,shodan,censys,securitytrails,virustotal,wayback,viewdns,dnsdumpster,zoomeye)
  --min-confidence float    Minimum confidence score for passive results (default: 0.7)
  
Advanced:
  --init-config             Initialize global config file
  --show-config             Show global config file path
  --update-waf              Update WAF IP ranges database
  -V, --version             Show version information
```

## 🔍 Response Verification

When scanning large IP ranges (especially ASNs), many IPs may return 200 OK but aren't the real origin server. Use `--verify` to identify unique responses:

```bash
# Basic scan (shows all 200 OK responses)
origindive -d example.com --asn AS18233 --skip-waf

# With verification (shows title and content hash)
origindive -d example.com --asn AS18233 --skip-waf --verify

# Filter to show only unique responses
origindive -d example.com --asn AS18233 --skip-waf --verify --filter-unique
```

**Output with `--verify`:**
```
[+] 192.0.2.10 --> 200 OK (331ms) | "Default Apache Page" [e2dd2d7e7a9cf514]
[+] 192.0.2.25 --> 200 OK (1.2s) | "Generic Web Server" [75f8453326f0c403]
[+] 192.0.2.50 --> 200 OK (518ms) | "Example Corporation" [f0d6e49d4ada8d7f]
```

**Content Hash Analysis:**
After scanning, you'll see a hash analysis showing which responses are unique:

```
═══════════════════════════════════════════════════════════════
  Content Hash Analysis
═══════════════════════════════════════════════════════════════
[*] Total unique responses: 15

[~] Hash e2dd2d7e7a9cf514 (5 IPs) - Shared response: "Default Apache Page"
    192.0.2.10
    192.0.2.15
    192.0.2.20
    198.51.100.5
    198.51.100.10

[✓] Hash f0d6e49d4ada8d7f (1 IP) - UNIQUE RESPONSE: "Example Corporation"
    192.0.2.50
```

**How to interpret:**
- **Green checkmark (✓)** = Unique response (only 1 IP returned this content)
- **Yellow tilde (~)** = Shared response (multiple IPs returned identical content)
- **Same hash** = Same website content (likely load balanced, default page, or shared hosting)
- **Unique hash** = Potentially the real origin server!

**Using `--filter-unique`:**
This flag automatically filters results to show only IPs with unique content hashes:

```bash
origindive -d example.com -i targets.txt --verify --filter-unique
```

Output: From 62 IPs with 200 OK → Shows only 41 IPs with unique content (filters out 21 duplicates)

Look for:
- ✅ Title matches your target domain
- ✅ Unique hash (marked with green ✓)
- ✅ Fastest response time (no CDN delay)

## 🌐 User Agent Customization

origindive supports flexible User-Agent configuration to bypass WAF detection or mimic real browsers:

### Usage Examples

```bash
# Use random browser user agent (changes for each scan)
origindive -d example.com -n 192.168.1.0/24 -A random

# Use random Chrome user agent (Windows/Mac/Linux)
origindive -d example.com -i targets.txt -A chrome

# Use random Firefox user agent
origindive -d example.com -i targets.txt -A firefox

# Use specific browser/platform combination
origindive -d example.com -i targets.txt -A chrome-windows
origindive -d example.com -i targets.txt -A firefox-mac
origindive -d example.com -i targets.txt -A safari-ios

# Use custom user agent string
origindive -d example.com -i targets.txt -A "MyCustomBot/1.0"

# Disable User-Agent header entirely
origindive -d example.com -i targets.txt --no-ua

# Use default origindive user agent (default behavior)
origindive -d example.com -i targets.txt
origindive -d example.com -i targets.txt -A default
```

### Supported Options

**Browser Names** (random UA from that browser):
- `random` - Random from all browsers (15 options)
- `chrome` - Chrome on Windows/Mac/Linux
- `firefox` - Firefox on Windows/Mac/Linux  
- `safari` - Safari on Mac/iOS
- `edge` - Edge on Windows/Mac
- `opera` - Opera on Windows/Mac
- `brave` - Brave on Windows/Mac
- `mobile` - Mobile browsers (Chrome Android, Safari iOS)

**Specific User Agents** (exact platform):
- `chrome-windows`, `chrome-mac`, `chrome-linux`
- `firefox-windows`, `firefox-mac`, `firefox-linux`
- `safari-mac`, `safari-ios`
- `edge-windows`, `edge-mac`
- `opera-windows`, `opera-mac`
- `brave-windows`, `brave-mac`
- `chrome-android`

**Custom String**: Any other value is used as-is

**Special Values**:
- `default` or empty - Uses `origindive/v3.1.0` (current version)
- `--no-ua` flag - Disables User-Agent header completely

### Use Cases

**Bypass WAF Detection**:
```bash
# Some WAFs block tool-specific user agents
origindive -d example.com -n 10.0.0.0/16 -A chrome --skip-waf
```

**Randomize for Each Scan**:
```bash
# Different UA each time you run
origindive -d example.com -i targets.txt -A random
```

**Test Server Behavior**:
```bash
# See if server responds differently to mobile vs desktop
origindive -d example.com -n 192.168.1.0/24 -A chrome-windows -o desktop.json
origindive -d example.com -n 192.168.1.0/24 -A safari-ios -o mobile.json
```

**Configuration File**:
```yaml
# config.yaml
domain: "example.com"
cidr: "192.168.1.0/24"
user_agent: "random"  # or "chrome", "firefox", etc.
skip_waf: true
workers: 20
```

## 🔒 Proxy Support

origindive supports HTTP and SOCKS5 proxies for anonymous scanning and bypassing geo-restrictions:

### Usage Examples

```bash
# Use specific HTTP proxy
origindive -d example.com -i targets.txt -P http://1.2.3.4:8080

# Use SOCKS5 proxy
origindive -d example.com -i targets.txt -P socks5://5.6.7.8:1080

# Use proxy with authentication
origindive -d example.com -i targets.txt -P http://user:pass@1.2.3.4:8080

# Auto-fetch free proxies from public lists
origindive -d example.com -i targets.txt --proxy-auto

# Auto-fetch proxies and rotate through them
origindive -d example.com -n 192.0.2.0/24 --proxy-auto --proxy-rotate

# Use proxy without testing (faster but may fail)
origindive -d example.com -i targets.txt -P http://1.2.3.4:8080 --proxy-test=false

# Combine with other features
origindive -d example.com --asn AS4775 --skip-waf -A random -P socks5://proxy:1080
```

### Proxy Modes

**1. Single Proxy** (`-P/--proxy`):
```bash
origindive -d example.com -i targets.txt -P http://1.2.3.4:8080
```
- Uses one proxy for all requests
- Supports: `http://`, `https://`, `socks5://`
- Optional authentication: `http://user:pass@host:port`

**2. Auto Proxy List** (`--proxy-auto`):
```bash
origindive -d example.com -i targets.txt --proxy-auto
```
- **Automatically fetches proxies from country-aware sources**:
  - **ProxyScrape API v4**: Country-specific, timeout=1000ms (fast proxies only)
  - **GeoNode API**: Country-specific, 90% uptime filter, sorted by last checked
- **Detects your country** from Cloudflare CDN trace (e.g., PH for Philippines)
- **Validates proxies** using 6 reliable IP check endpoints with fallback
- **Falls back** to direct connection if no proxies work
- **Premium support**: Webshare.io integration (configured in global config)

**3. Webshare.io Premium Proxies**:
```bash
# Configure in ~/.config/origindive/config.yaml
webshare_keys:
  - "your-api-token-here"

# Then use with --proxy-auto
origindive -d example.com -i targets.txt --proxy-auto
```
- **Professional proxy service** (requires subscription)
- **High-quality datacenter proxies** across multiple countries
- **Automatic fetching** when API key configured
- **Priority validation**: Premium proxies placed first in list
- **See**: `configs/global.example.yaml` for configuration

**4. Proxy Rotation** (`--proxy-rotate`):
```bash
origindive -d example.com -i targets.txt --proxy-auto --proxy-rotate
```
- Rotates through proxy list for each HTTP request
- Distributes load across multiple proxies
- Reduces ban risk from rate limiting

### Proxy Testing

By default, proxies are tested before use:

```bash
# Test enabled (default) - slower but reliable
origindive -d example.com -i targets.txt -P http://proxy:8080

# Disable testing - faster but may encounter failures
origindive -d example.com -i targets.txt -P http://proxy:8080 --proxy-test=false
```

**Test Process**:
1. Connects to proxy
2. Makes test request to `https://httpbin.org/ip`
3. Verifies 200 OK response
4. Rejects proxy if test fails

### Configuration File

```yaml
# config.yaml
domain: "example.com"
cidr: "192.0.2.0/24"

# Proxy settings
proxy_url: "http://1.2.3.4:8080"  # Single proxy
proxy_auto: false                  # Auto-fetch from public lists
proxy_rotate: false                # Rotate through proxies
proxy_test: true                   # Test before use

skip_waf: true
workers: 20
```

### Public Proxy Sources

When using `--proxy-auto`, proxies are fetched from:

**Country-Aware Sources** (automatic geo-detection):
- **ProxyScrape API v4**: `country={detected}&timeout=1000`
  - Fast proxies only (<1 second response time)
  - Country-specific for lower latency
  - JSON format with protocol support
  
- **GeoNode API**: `country={detected}&filterUpTime=90`
  - 90%+ uptime filter for reliability
  - Sorted by last checked (freshest first)
  - Supports HTTP, HTTPS, SOCKS4, SOCKS5

**Premium Source** (requires API key):
- **Webshare.io**: Professional datacenter proxies
  - Configure in `~/.config/origindive/config.yaml`
  - High-quality, authenticated proxies
  - Multiple countries available

**Detection**: Country auto-detected from `https://cloudflare.com/cdn-cgi/trace` (loc=XX)

**Performance** (Philippines example):
- Before: 675 global proxies, 1.90% working
- After: 174 PH proxies, 5.75% working (3x better quality)

**Note**: Free proxies may be:
- ❌ Slow or unreliable
- ❌ Blocked by some services  
- ❌ Monitored or malicious
- ✅ Useful for bypassing geo-restrictions
- ✅ Good for distributing scan load
- ✅ Country-aware = better latency

### Use Cases

**Bypass Geo-Restrictions**:
```bash
# Use SOCKS5 proxy in target country
origindive -d example.com -i targets.txt -P socks5://country-proxy:1080
```

**Avoid IP Bans**:
```bash
# Rotate through multiple proxies
origindive -d example.com --asn AS4775 --proxy-auto --proxy-rotate -j 5
```

**Anonymous Scanning**:
```bash
# Hide your real IP
origindive -d example.com -i targets.txt -P socks5://tor-proxy:9050
```

**Large-Scale Scans**:
```bash
# Distribute across proxy pool with random UA
origindive -d example.com -n 10.0.0.0/16 --proxy-auto --proxy-rotate -A random -j 10
```

### Troubleshooting

**No working proxies found**:
```bash
# Try increasing workers for parallel validation
origindive -d example.com --proxy-auto -j 20

# Or use a specific known-working proxy
origindive -d example.com -P http://your-proxy:8080
```

**Proxy connection timeouts**:
```bash
# Increase timeout
origindive -d example.com -P http://slow-proxy:8080 -t 15

# Disable proxy testing
origindive -d example.com -P http://slow-proxy:8080 --proxy-test=false
```

**0 results with proxy**:
```bash
# Test proxy manually first
origindive -d example.com -s 192.0.2.1 -e 192.0.2.5 -P http://proxy:8080 --verify

# Try without proxy to verify IPs respond
origindive -d example.com -s 192.0.2.1 -e 192.0.2.5
```

## 🛡️ WAF Filtering

One of the killer features of origindive v3 is intelligent WAF/CDN filtering.

### Why WAF Filtering?

When scanning large IP ranges, you'll waste time testing known CDN/WAF IPs that will never be origin servers. origindive maintains a database of 108+ CIDR ranges for major providers.

### Usage

```bash
# Skip all known WAF IPs
origindive -d example.com -n 0.0.0.0/8 --skip-waf -j 50

# Skip only Cloudflare and AWS
origindive -d example.com -i targets.txt --skip-providers cloudflare,aws-cloudfront

# Show what gets skipped
origindive -d example.com -n 23.0.0.0/16 --skip-waf --show-skipped

# Use custom WAF ranges
origindive -d example.com -n 10.0.0.0/8 --custom-waf my-waf-ranges.txt
```

### Supported Providers

- **Cloudflare** - 15 ranges
- **AWS CloudFront** - 44 ranges
- **Fastly** - 18 ranges
- **Akamai** - 12 ranges
- **Incapsula/Imperva** - 12 ranges
- **Sucuri** - 7 ranges

### WAF Management

```bash
# List all known providers
origindive waf list

# Update WAF ranges from official APIs
origindive waf update

# Check when last updated
origindive waf info
```

### Auto-Updates

WAF ranges are automatically updated weekly from official provider APIs:
- Cloudflare: https://www.cloudflare.com/ips-v4
- AWS: https://ip-ranges.amazonaws.com/ip-ranges.json
- Fastly: https://api.fastly.com/public-ip-list

Disable with `--no-waf-update` flag.

## ⚙️ Configuration

### YAML Configuration File

Create `origindive.yaml`:

```yaml
# Target configuration
domain: "example.com"

# IP ranges
cidr: "192.168.1.0/24"
# or use: start_ip / end_ip / input_file

# Performance
workers: 20
timeout: "5s"
connect_timeout: "3s"

# WAF filtering
skip_waf: true
skip_providers:
  - cloudflare
  - aws-cloudfront
show_skipped: false

# Output
output_file: "results.json"
format: "json"
show_all: false

# HTTP
http_method: "GET"
```

Use with:
```bash
origindive --config origindive.yaml
```

See `configs/example.yaml` for all options.

## 📊 Output Formats

### Text (Default)

```
[+] 192.0.2.10 --> 200 OK (23.45ms)
[+] 192.0.2.15 --> 200 OK (19.32ms)
[>] 192.0.2.20 --> HTTP 301 (Redirect)
```

### JSON

```bash
origindive -d example.com -n 192.168.1.0/24 -f json -o results.json
```

```json
{
  "domain": "example.com",
  "mode": "active",
  "success": [
    {
      "ip": "192.0.2.10",
      "status": "200",
      "http_code": 200,
      "response_time": "23.45ms"
    }
  ],
  "summary": {
    "total_ips": 254,
    "scanned_ips": 254,
    "skipped_ips": 0,
    "success_count": 2,
    "duration": "12.5s"
  }
}
```

### CSV

```bash
origindive -d example.com -n 192.168.1.0/24 -f csv -o results.csv
```

```csv
IP,Status,HTTPCode,ResponseTime,Error
192.0.2.10,200,200,23.45ms,
192.0.2.15,200,200,19.32ms,
```

## 🔄 Migration from v2.x

origindive v3.0 is a complete rewrite. Key changes:

### Breaking Changes

| v2.x (originfind) | v3.0 (origindive) |
|-------------------|-------------------|
| `originfind` | `origindive` |
| No WAF filtering | `--skip-waf` flag |
| Text output only | `--format text\|json\|csv` |
| No config files | `--config yaml` support |
| Go 1.16+ | Go 1.23+ required |

### Command Migration

```bash
# v2.x (legacy originfind)
originfind -d example.com -n 192.168.1.0/24 -j 10 -o results.txt

# v3.0 equivalent
origindive -d example.com -n 192.168.1.0/24 -j 10 -o results.txt

# v3.0 with WAF filtering
origindive -d example.com -n 192.168.1.0/24 -j 10 --skip-waf -o results.txt
```

Most flags remain the same. See `MIGRATION.md` for detailed guide.

## 📈 Performance Tips

- **Workers**: 
  - 10-20 for internet scans (default: 10)
  - 50+ for local networks
  - **Lower to 3-5 if getting timeouts or 0 results** (server rate limiting)
- **Timeout**:
  - Default 5s works for most cases
  - **Increase to 10-15s for slow/rate-limited servers** (`-t 10`)
- **WAF Filtering**: Always use `--skip-waf` for large scans
- **Progress Bar**: Disable with `--no-progress` for scripting
- **Output**: Use JSON format for parsing results programmatically

### Troubleshooting: Getting 0 Results

If you know IPs should return 200 OK but get 0 results:

```bash
# Problem: Too many simultaneous connections (server drops requests)
origindive -d example.com -i ips.txt           # 0 results with default -j 10

# Solution 1: Reduce workers
origindive -d example.com -i ips.txt -j 3      # Works! Slower but reliable

# Solution 2: Increase timeout
origindive -d example.com -i ips.txt -t 15     # Allows slow responses

# Best: Combine both
origindive -d example.com -i ips.txt -j 5 -t 10  # Recommended for rate-limited servers
```

## 🔒 Legal Disclaimer

**IMPORTANT**: Only scan systems you are authorized to test.

- Unauthorized scanning may be illegal in your jurisdiction
- Always obtain explicit permission before testing
- Use responsibly for security research and penetration testing
- The authors are not responsible for misuse

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md).

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fjhaxce%2Forigindive.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fjhaxce%2Forigindive?ref=badge_large)

## 🙏 Acknowledgments

- Built with Go's excellent standard library
- Inspired by the security research community
- WAF ranges sourced from official provider APIs

---

**Made with 💖 by [jhaxce](https://github.com/jhaxce)**

For issues and feature requests: https://github.com/jhaxce/origindive/issues
