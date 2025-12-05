# Command-Line Flag Reference

Complete guide to all origindive command-line flags with detailed explanations for complex or ambiguous options.

## Table of Contents

- [Target Specification](#target-specification)
- [IP Range Specification](#ip-range-specification)
- [Scan Modes](#scan-modes)
- [Performance Tuning](#performance-tuning)
- [HTTP Configuration](#http-configuration)
- [Response Verification](#response-verification)
- [Proxy Configuration](#proxy-configuration)
- [WAF/CDN Filtering](#wafcdn-filtering)
- [Passive Reconnaissance](#passive-reconnaissance)
- [Output Configuration](#output-configuration)
- [Utility Flags](#utility-flags)

---

## Target Specification

### `-d, --domain <domain>`
**Required** (except for utility commands)

The target domain to test. Used in HTTP Host header when scanning IPs.

```bash
# Basic usage
origindive -d example.com -n 192.0.2.0/24

# Subdomain
origindive -d api.example.com -n 192.0.2.0/24

# Works with any valid domain
origindive -d my-app.herokuapp.com --asn AS54113
```

**Why it matters:**
- The scanner sends HTTP requests to IPs with `Host: example.com` header
- Origin servers are configured to respond to specific domain names
- Using wrong domain = no matches, even if IP is correct

**Technical details:**
- Domain validation: Must be valid DNS name (alphanumeric, hyphens, dots)
- Case-insensitive (converted to lowercase internally)
- No protocol prefix (use `example.com`, not `https://example.com`)

---

## IP Range Specification

You must specify at least ONE of these (or use `--passive` mode):

### `-s, --start-ip <ip>` + `-e, --end-ip <ip>`
Scan a continuous range of IP addresses.

```bash
# Scan 192.0.2.1 through 192.0.2.254
origindive -d example.com -s 192.0.2.1 -e 192.0.2.254

# Single IP (start = end)
origindive -d example.com -s 192.0.2.10 -e 192.0.2.10
```

**Use when:**
- You have a specific IP range from reconnaissance
- Testing sequential IPs in a subnet
- You know the exact boundaries

**Limitations:**
- Both flags required (can't use just `-s` or just `-e`)
- Only supports single continuous range
- For multiple ranges, use `-i` with a file

---

### `-c, --cidr <cidr>`
Scan an entire CIDR block.

```bash
# Scan 192.0.2.0 - 192.0.2.255 (256 IPs)
origindive -d example.com -c 192.0.2.0/24

# Scan 10.0.0.0 - 10.0.3.255 (1,024 IPs)
origindive -d example.com -c 10.0.0.0/22

# Single IP as /32
origindive -d example.com -c 192.0.2.10/32
```

**CIDR Sizes:**
- `/32` = 1 IP (single host)
- `/31` = 2 IPs (point-to-point link, RFC 3021)
- `/30` = 4 IPs (network, 2 usable, broadcast)
- `/24` = 256 IPs (254 usable, common subnet)
- `/20` = 4,096 IPs (recommended max for scanning)
- `/16` = 65,536 IPs (⚠️ very slow without --skip-waf)
- `/8` = 16,777,216 IPs (❌ not recommended)

**Performance tips:**
```bash
# Large CIDR? Enable WAF filtering
origindive -d example.com -c 104.16.0.0/12 --skip-waf -j 50

# Even larger? Filter specific providers
origindive -d example.com -c 0.0.0.0/8 --skip-providers cloudflare,aws-cloudfront
```

**Warning messages:**
```
[!] Warning: CIDR 10.0.0.0/8 is very large (16777216 IPs)
[*] Recommended: Use --skip-waf to filter known CDN/WAF ranges
[*] Estimated scan time: ~46 hours at 10 req/s
```

---

### `-i, --input <file>`
Load IP addresses, CIDR ranges, or IP ranges from a file.

**File format** (flexible, one per line):
```text
# Single IPs
192.0.2.10
192.0.2.15

# CIDR notation
192.0.2.0/28
10.0.1.0/24

# IP ranges (dash notation)
192.0.2.100-192.0.2.200
10.0.5.1-10.0.5.50

# Comments (ignored)
# This is a comment
192.0.2.50  # inline comment also works

# Blank lines (ignored)

203.0.113.0/24
```

```bash
# Basic usage
origindive -d example.com -i targets.txt

# Combine with other options
origindive -d example.com -i ips.txt --skip-waf -j 20 -o results.json
```

**Use when:**
- Scanning results from passive recon
- Multiple non-contiguous ranges
- Sharing target lists with team
- Scanning discovered IPs from previous runs

**Technical details:**
- Max file size: Unlimited (limited by available memory)
- Duplicates: Automatically merged (192.0.2.10 + 192.0.2.10/32 = scanned once)
- Overlapping ranges: Automatically merged (192.0.2.0/24 + 192.0.2.0/25 = /24)
- Invalid lines: Reported with line numbers, scan continues

---

### `--asn <asn>`
Automatically fetch CIDR ranges for ASN(s) and scan them.

```bash
# Single ASN (with or without "AS" prefix)
origindive -d example.com --asn AS13335
origindive -d example.com --asn 13335

# Multiple ASNs (comma-separated)
origindive -d example.com --asn AS13335,AS15169,AS8075

# Mixed format
origindive -d example.com --asn AS13335,15169,AS8075
```

**How it works:**
1. Queries ipapi.is API for ASN details
2. Downloads all CIDR ranges for the ASN
3. Merges overlapping ranges
4. Scans all IPs in those ranges

**Example output:**
```
[*] Looking up ASN: AS13335
[+] Found 158 CIDR ranges for AS13335 (Cloudflare, Inc.)
    ├─ Total IPs: 2,745,856
    ├─ Largest: 104.16.0.0/12 (1,048,576 IPs)
    └─ Cached: /home/user/.cache/origindive/asn/AS13335.json

[*] Scanning 2,745,856 IPs across 158 ranges...
```

**Use when:**
- Target uses specific hosting provider (AWS, DigitalOcean, etc.)
- Discovering infrastructure in cloud providers
- Testing all IPs owned by organization

**Performance:**
```bash
# ASN scanning is SLOW without filtering
# ⚠️ Bad: 2.7M IPs, will take days
origindive -d example.com --asn AS13335

# ✅ Good: Skip Cloudflare WAF ranges, focus on origin IPs
origindive -d example.com --asn AS13335 --skip-waf

# ✅ Better: High concurrency, WAF filtering
origindive -d example.com --asn AS13335 --skip-waf -j 100
```

**API limits:**
- Service: ipapi.is (free, no key required)
- Rate limit: Unknown (reasonable use)
- Fallback: Manual CIDR input if API fails

**Caching:**
- Location: `~/.cache/origindive/asn/`
- Format: JSON (permanent cache)
- Update: Only fetched once per ASN, never expires
- Manual refresh: Delete cache file and re-run

See [ASN_LOOKUP.md](ASN_LOOKUP.md) for advanced usage.

---

### `-n, --expand-netmask <cidr>`
**Passive mode only** - Expand discovered IPs to their subnet.

```bash
# Discover IPs, then scan entire /24 subnet for each
origindive -d example.com --passive -n /24

# Discover IPs, scan /16 subnet for each
origindive -d example.com --passive -n 16

# Works in auto mode (passive → active)
origindive -d example.com --auto-scan -n /24
```

**How it works:**
```
Passive recon finds: 192.0.2.45

Without -n:
└─ Scans: 192.0.2.45 only

With -n /24:
└─ Scans: 192.0.2.0/24 (all 256 IPs)

With -n /16:
└─ Scans: 192.0.0.0/16 (all 65,536 IPs)
```

**Use when:**
- Passive finds single IP, but origin might be load-balanced
- Expanding to scan entire subnet where server resides
- Finding all IPs in same network segment

**Example scenario:**
```bash
# Step 1: Passive recon finds 203.0.113.42
origindive -d example.com --passive

# Step 2: Expand to /24 and scan
origindive -d example.com --passive -n /24

# Result: Scans 203.0.113.0-255, finds 203.0.113.42, .43, .44 (load balanced)
```

**Warning:**
```bash
# ⚠️ Be careful with small netmasks (large subnets)
origindive -d example.com --passive -n /8
# If passive finds 10.0.0.1, this scans 16.7M IPs!
```

**Technical details:**
- Applied AFTER passive recon completes
- Each discovered IP expanded independently
- Overlapping subnets automatically merged
- Only works in `--passive` or `--auto-scan` modes
- Ignored in pure active mode (`-c`, `-s`/`-e`, `-i`)

---

## Scan Modes

### `--passive`
Run passive reconnaissance ONLY (no active scanning).

```bash
# Discover IPs from OSINT sources
origindive -d example.com --passive

# Use specific sources
origindive -d example.com --passive --passive-sources ct,shodan,virustotal

# Save to file
origindive -d example.com --passive -o discovered.txt
```

**What it does:**
- Queries 9 OSINT intelligence sources
- Returns IPs with confidence scores
- NO HTTP requests to target
- Outputs discovered IPs and sources

**Output:**
```
[PASSIVE] Certificate Transparency
  ├─ 192.0.2.10 (confidence: 0.92)
  └─ 192.0.2.15 (confidence: 0.85)

[PASSIVE] Shodan
  └─ 192.0.2.10 (confidence: 0.95)

Discovered: 2 unique IPs
Cross-verified: 1 IP (192.0.2.10 in 2 sources)
```

**Use when:**
- Initial reconnaissance
- Avoiding detection (no active scanning)
- Building target list for later active scan
- Researching infrastructure

See [PASSIVE_RECONNAISSANCE.md](PASSIVE_RECONNAISSANCE.md) for details.

---

### `--auto-scan`
Passive reconnaissance followed by active scanning.

```bash
# Discover IPs, then scan them
origindive -d example.com --auto-scan

# Discover IPs, expand to /24, scan all
origindive -d example.com --auto-scan -n /24

# Discover + scan with options
origindive -d example.com --auto-scan -j 50 --verify
```

**Workflow:**
```
1. Run passive recon (query all OSINT sources)
2. Collect discovered IPs
3. Optionally expand to subnets (-n flag)
4. Active scan all IPs with HTTP requests
5. Output results
```

**Example:**
```
═══════════════════════════════════════════════════
  Starting Passive Reconnaissance
═══════════════════════════════════════════════════

[PASSIVE] Certificate Transparency: 3 IPs
[PASSIVE] Shodan: 2 IPs
[PASSIVE] VirusTotal: 1 IP

[+] Passive reconnaissance complete: 5 IPs discovered
═══════════════════════════════════════════════════

[*] Proceeding with active scan on 5 discovered IPs

═══════════════════════════════════════════════════
  Starting Active Scan
═══════════════════════════════════════════════════

[+] 192.0.2.10 --> 200 OK (123ms)
[+] 192.0.2.15 --> 200 OK (234ms)

Success: 2/5 IPs returned 200 OK
```

**Use when:**
- You want comprehensive discovery + validation
- Building complete workflow in one command
- Don't know exact IP ranges beforehand

---

### Default Mode (Active Only)
If neither `--passive` nor `--auto-scan` specified, runs active scan only.

```bash
# Active scan on specified range
origindive -d example.com -c 192.0.2.0/24

# Requires IP range specification (-c, -s/-e, -i, or --asn)
```

---

## Performance Tuning

### `-j, --threads <count>`
Number of parallel workers (goroutines) for scanning.

**Default:** 10 workers

```bash
# Low concurrency (polite scanning)
origindive -d example.com -c 192.0.2.0/24 -j 5

# Default
origindive -d example.com -c 192.0.2.0/24 -j 10

# High concurrency (fast scanning)
origindive -d example.com -c 192.0.2.0/24 -j 50

# Very high (use with caution)
origindive -d example.com -c 192.0.2.0/24 -j 100
```

**Performance impact:**

| Workers | Scan Rate | 1000 IPs | 10000 IPs | Use Case |
|---------|-----------|----------|-----------|----------|
| 5 | ~5/sec | 3 min | 33 min | Polite, avoiding detection |
| 10 | ~10/sec | 1.5 min | 16 min | Default balanced |
| 20 | ~20/sec | 50 sec | 8 min | Faster scans |
| 50 | ~50/sec | 20 sec | 3 min | Large ranges |
| 100 | ~100/sec | 10 sec | 1.5 min | Massive ranges (may trigger WAF) |

**Warning signs (too many workers):**
```
[!] Warning: 85% of requests failed
[!] The server may be rate-limiting connections
[*] Try: Reduce workers (-j 5) and increase timeout (-t 10)
```

**Technical details:**
- Each worker maintains its own HTTP connection pool
- Memory usage: ~1-2 MB per worker
- CPU usage: Minimal (I/O bound, not CPU bound)
- Network: Limited by bandwidth and target capacity

**Best practices:**
```bash
# Small ranges (< 1000 IPs): Default is fine
origindive -d example.com -c 192.0.2.0/24

# Large ranges (1K-10K): Increase workers
origindive -d example.com --asn AS13335 --skip-waf -j 50

# Massive ranges (> 10K): Max workers + WAF filtering
origindive -d example.com -c 104.16.0.0/12 --skip-waf -j 100

# Rate-limited targets: Reduce workers
origindive -d example.com -c 192.0.2.0/24 -j 3 -t 10
```

---

### `-t, --timeout <seconds>`
HTTP request timeout (waiting for response).

**Default:** 5 seconds

```bash
# Fast timeout (impatient, may miss slow servers)
origindive -d example.com -c 192.0.2.0/24 -t 2

# Default (balanced)
origindive -d example.com -c 192.0.2.0/24 -t 5

# Slow servers (patient)
origindive -d example.com -c 192.0.2.0/24 -t 15

# Very slow servers or proxies
origindive -d example.com -c 192.0.2.0/24 -t 30
```

**What it controls:**
- Time waiting for HTTP response (total request time)
- Includes: DNS lookup + TCP connect + TLS handshake + HTTP response
- Does NOT include time waiting in queue (covered by workers)

**When to increase:**
```bash
# Seeing many timeouts
[+] 192.0.2.10 --> Timeout
[+] 192.0.2.11 --> Timeout
# Solution: Increase timeout
origindive -d example.com -c 192.0.2.0/24 -t 10

# Using slow proxies
origindive -d example.com --proxy-auto -t 15

# Scanning from slow network connection
origindive -d example.com -c 192.0.2.0/24 -t 20
```

**When to decrease:**
```bash
# Fast local network
origindive -d example.com -c 192.168.1.0/24 -t 2

# Scanning cloud IPs (fast response expected)
origindive -d example.com --asn AS16509 -t 3
```

**Trade-offs:**
- **Low timeout (2-3s):** Fast scans, may miss slow servers, more false negatives
- **Medium timeout (5-7s):** Balanced (recommended)
- **High timeout (10-30s):** Catches slow servers, slower scans, may hide issues

**Technical details:**
- Applied per HTTP request
- Separate from `--connect-timeout` (TCP handshake)
- Uses Go's `context.WithTimeout`
- Aborts request immediately on timeout

---

### `--connect-timeout <seconds>`
TCP connection timeout (before HTTP request).

**Default:** 3 seconds

```bash
# Fast connection timeout
origindive -d example.com -c 192.0.2.0/24 --connect-timeout 1 -t 5

# Default
origindive -d example.com -c 192.0.2.0/24 --connect-timeout 3 -t 5

# Slow networks
origindive -d example.com -c 192.0.2.0/24 --connect-timeout 10 -t 15
```

**Difference from `--timeout`:**
```
--connect-timeout: Time to establish TCP connection
     └─ TCP SYN → SYN-ACK → ACK

--timeout: Total HTTP request time
     └─ Connect + TLS handshake + HTTP request + response
```

**Example:**
```bash
# Target server very slow to accept connections
# But responds quickly once connected
origindive -d example.com -c 192.0.2.0/24 --connect-timeout 10 -t 5

# Target accepts connections quickly but processes slowly
origindive -d example.com -c 192.0.2.0/24 --connect-timeout 2 -t 15
```

**Use when:**
- Firewall delays TCP handshake (SYN flood protection)
- Scanning through slow proxies
- High latency networks (satellite, international)

---

## HTTP Configuration

### `-m, --method <method>`
HTTP request method.

**Default:** GET

```bash
# GET (default)
origindive -d example.com -c 192.0.2.0/24

# HEAD (faster, less bandwidth)
origindive -d example.com -c 192.0.2.0/24 -m HEAD

# POST (if origin expects POST)
origindive -d example.com -c 192.0.2.0/24 -m POST

# OPTIONS (check allowed methods)
origindive -d example.com -c 192.0.2.0/24 -m OPTIONS
```

**Use cases:**

**GET (default):**
- Most common, returns full response body
- Required for `--verify` (content verification)
- Use for normal scanning

**HEAD:**
- Only returns headers (no body)
- Faster (less data transfer)
- Can't use with `--verify`
- Good for large-scale scanning
- Some servers respond differently to HEAD vs GET

**POST:**
- If target origin server only responds to POST
- Testing POST endpoints
- Rare use case

**Technical details:**
- Method applied to ALL requests
- Can't mix methods in single scan
- Some servers return different status codes (HEAD 404, GET 200)

---

### `-H, --header <header>`
Add custom HTTP header to requests.

```bash
# Single header
origindive -d example.com -c 192.0.2.0/24 -H "X-Forwarded-For: 127.0.0.1"

# Authentication
origindive -d example.com -c 192.0.2.0/24 -H "Authorization: Bearer token123"

# Custom header
origindive -d example.com -c 192.0.2.0/24 -H "X-Custom-Header: value"
```

**Format:** `"Header-Name: Header-Value"`

**Multiple headers:**
```bash
# Currently: Only ONE custom header supported
# Workaround: Combine in config file

# config.yaml
custom_header: "X-Forwarded-For: 127.0.0.1"
```

**Automatic headers (always sent):**
- `Host: <domain>` (from `-d` flag)
- `User-Agent: origindive/3.1.0` (unless `--no-ua` or `-A` used)
- `Accept: */*`
- `Connection: keep-alive`

**Use cases:**
- Bypassing IP restrictions with `X-Forwarded-For`
- Testing authenticated endpoints
- Simulating specific client headers
- Debugging header-based routing

---

### `-A, --user-agent <preset|custom>`
Set User-Agent header.

```bash
# Presets
origindive -d example.com -c 192.0.2.0/24 -A chrome
origindive -d example.com -c 192.0.2.0/24 -A firefox
origindive -d example.com -c 192.0.2.0/24 -A safari
origindive -d example.com -c 192.0.2.0/24 -A edge
origindive -d example.com -c 192.0.2.0/24 -A opera
origindive -d example.com -c 192.0.2.0/24 -A brave
origindive -d example.com -c 192.0.2.0/24 -A mobile
origindive -d example.com -c 192.0.2.0/24 -A random

# Custom string
origindive -d example.com -c 192.0.2.0/24 -A "MyCustomBot/1.0"
```

**Presets:**
- `chrome` - Latest Chrome on Windows
- `firefox` - Latest Firefox on Windows
- `safari` - Latest Safari on macOS
- `edge` - Latest Edge on Windows
- `opera` - Latest Opera on Windows
- `brave` - Latest Brave on Windows
- `mobile` - Mobile Chrome on Android
- `random` - Randomly chosen from above each request

**Use cases:**
```bash
# Server blocks default User-Agent "origindive"
origindive -d example.com -c 192.0.2.0/24 -A chrome

# Simulating mobile traffic
origindive -d example.com -c 192.0.2.0/24 -A mobile

# Random UA to avoid pattern detection
origindive -d example.com -c 192.0.2.0/24 -A random

# Custom scanner identification
origindive -d example.com -c 192.0.2.0/24 -A "CompanySecurityScan/2.0"
```

### `--no-ua`
Disable User-Agent header completely.

```bash
# Don't send User-Agent at all
origindive -d example.com -c 192.0.2.0/24 --no-ua
```

**Use when:**
- Testing server behavior without User-Agent
- Minimal HTTP footprint
- Bypassing UA-based blocking

**Conflict:**
```bash
# Error: Can't use both
origindive -d example.com -c 192.0.2.0/24 -A chrome --no-ua
# Use one or the other
```

---

## Response Verification

### `--verify`
Extract and display response content details for verification.

```bash
# Enable content verification
origindive -d example.com -c 192.0.2.0/24 --verify
```

**What it extracts:**
1. **HTML Title** - `<title>` tag content (first 100 chars)
2. **Body Hash** - SHA256 hash of response body (first 16 chars)
3. **Server Header** - Server software (if present)
4. **Content-Type** - Response content type

**Output:**
```
Without --verify:
[+] 192.0.2.10 --> 200 OK (123ms)

With --verify:
[+] 192.0.2.10 --> 200 OK (123ms) | "My Website" [a3b5c8d1e4f7]
                                    ^title^      ^body hash^
```

**Use cases:**

**Problem:** Too many false positives
```bash
# Many 200 OK, but which is real origin?
origindive -d example.com --asn AS18233 --skip-waf

# Results:
[+] 192.0.2.10 --> 200 OK (123ms)  ← Real origin?
[+] 192.0.2.11 --> 200 OK (234ms)  ← Shared hosting?
[+] 192.0.2.12 --> 200 OK (345ms)  ← Default page?
[+] 192.0.2.13 --> 200 OK (456ms)  ← Load balancer?
```

**Solution:** Use `--verify`
```bash
origindive -d example.com --asn AS18233 --skip-waf --verify

# Results:
[+] 192.0.2.10 --> 200 OK (123ms) | "My Website" [a3b5c8d1e4f7]  ← REAL!
[+] 192.0.2.11 --> 200 OK (234ms) | "Shared Hosting" [b4c6d8e1]  ← Different site
[+] 192.0.2.12 --> 200 OK (345ms) | "Apache Default" [c5d7e9f1]  ← Default page
[+] 192.0.2.13 --> 200 OK (456ms) | "My Website" [a3b5c8d1e4f7]  ← Duplicate (load balancer)

Duplicate content analysis:
  a3b5c8d1e4f7: 2 IPs (192.0.2.10, 192.0.2.13) ← Real origin servers
  b4c6d8e1: 1 IP (different content)
  c5d7e9f1: 1 IP (different content)
```

**Finding duplicates:**
- Same hash = Same content = Likely same server/load balanced
- Different hash = Different content = False positive

**Performance impact:**
- Downloads full response body (more bandwidth)
- Computes SHA256 hash (minimal CPU)
- Slightly slower scans (~10-20%)
- Required for `--filter-unique`

---

### `--filter-unique`
Show only IPs with unique response content (requires `--verify`).

```bash
# Filter to unique responses only
origindive -d example.com -c 192.0.2.0/24 --verify --filter-unique
```

**How it works:**
```
Step 1: Scan with --verify
  ├─ 192.0.2.10 --> "My Website" [hash1]
  ├─ 192.0.2.11 --> "My Website" [hash1]  ← Duplicate
  ├─ 192.0.2.12 --> "Apache Default" [hash2]
  └─ 192.0.2.13 --> "Nginx Default" [hash3]

Step 2: Group by content hash
  ├─ hash1: 2 IPs (192.0.2.10, .11)
  ├─ hash2: 1 IP (192.0.2.12)
  └─ hash3: 1 IP (192.0.2.13)

Step 3: Filter to singles only
  ├─ 192.0.2.12 --> "Apache Default" [hash2]  ✓
  └─ 192.0.2.13 --> "Nginx Default" [hash3]   ✓

Output: 2 unique responses (filtered out 2 duplicates)
```

**Use when:**
- Large ASN scans return many duplicates
- Finding distinct servers (not load-balanced pairs)
- Removing false positives from shared hosting

**Example:**
```bash
# Scan Cloudflare ASN (normally 100+ matches, mostly duplicates)
origindive -d example.com --asn AS13335 --skip-waf --verify --filter-unique

# Result: Only 5 unique responses (filtered 95 duplicates)
[+] 104.16.1.10 --> "My Website" [a3b5c8d1]
[+] 104.16.2.20 --> "API Gateway" [b4c6d8e1]
[+] 104.16.3.30 --> "Admin Panel" [c5d7e9f1]
[+] 104.16.4.40 --> "Default Page" [d6e8f1a3]
[+] 104.16.5.50 --> "Old Version" [e7f9a1b3]

[*] Filtered to 5 unique response(s)
```

**Limitation:**
- Requires `--verify` flag
- Groups by exact content hash (minor changes = different hash)
- Can't filter by title or server header alone

---

## Proxy Configuration

### `-P, --proxy <url>`
Use a specific proxy for all requests.

```bash
# HTTP proxy
origindive -d example.com -c 192.0.2.0/24 -P http://proxy.example.com:8080

# HTTPS proxy (CONNECT tunnel)
origindive -d example.com -c 192.0.2.0/24 -P https://proxy.example.com:3128

# SOCKS5 proxy (recommended for anonymity)
origindive -d example.com -c 192.0.2.0/24 -P socks5://proxy.example.com:1080

# SOCKS4 proxy
origindive -d example.com -c 192.0.2.0/24 -P socks4://proxy.example.com:1080

# Authenticated proxy
origindive -d example.com -c 192.0.2.0/24 -P http://user:pass@proxy.example.com:8080
```

**Use when:**
- Scanning from different IP/location
- Bypassing IP restrictions
- Hiding your identity
- Testing through corporate proxy

**Testing proxy:**
```bash
# Test proxy before scanning
curl -x http://proxy:8080 http://ipinfo.io/ip
```

See [PROXY_GUIDE.md](PROXY_GUIDE.md) for details.

---

### `--proxy-auto`
Automatically fetch and use proxies from public sources.

```bash
# Auto-fetch country-specific proxies
origindive -d example.com -c 192.0.2.0/24 --proxy-auto

# With Webshare.io FREE proxies (10 premium proxies)
origindive -d example.com -c 192.0.2.0/24 --proxy-auto --webshare-key YOUR_KEY
```

**How it works:**
```
1. Detect your country (Cloudflare CDN trace)
   └─ Example: Philippines (PH)

2. Fetch country-specific proxies
   ├─ ProxyScrape (PH, timeout ≤1000ms): 82 proxies
   ├─ GeoNode (PH, uptime ≥90%): 92 proxies
   └─ Webshare.io (premium, if key provided): 10 proxies

3. Validate proxies (smart sampling)
   ├─ First 50 always validated (includes Webshare premium)
   ├─ Remaining: 20% random sample (max 2,000)
   └─ Test with 6 IP check endpoints

4. Use working proxies for scan
   ├─ Found 13 working proxies
   └─ Rotate through them during scan
```

**Performance:**
- Country-aware = 74% fewer proxies to validate
- Geo-local proxies = Lower latency
- Smart sampling = 3x faster validation
- Webshare premium = 90%+ success rate

**Sources:**
1. **Webshare.io** (premium, if API key provided)
   - 10 free datacenter proxies
   - Sign up: https://www.webshare.io/
   - 90%+ working rate

2. **ProxyScrape v4** (free, country-aware)
   - Filtered by your country
   - Timeout ≤1000ms (fast proxies only)
   - 5-10% working rate

3. **GeoNode** (free, country-aware + uptime)
   - Filtered by your country
   - Uptime ≥90% (reliable proxies)
   - 5-10% working rate

**Configuration:**
```yaml
# ~/.config/origindive/config.yaml
webshare_keys:
  - "YOUR_WEBSHARE_API_KEY"

proxy_auto: true
proxy_workers: 50  # Validation speed
proxy_test_timeout: 60  # Validation timeout
```

See [PROXY_GUIDE.md](PROXY_GUIDE.md) for troubleshooting.

---

### `--proxy-rotate`
Rotate through multiple proxies during scan.

```bash
# Enable proxy rotation (default when using --proxy-auto)
origindive -d example.com -c 192.0.2.0/24 --proxy-auto --proxy-rotate

# Disable rotation (use same proxy for all requests)
origindive -d example.com -c 192.0.2.0/24 --proxy-auto --no-proxy-rotation
```

**With rotation:**
```
Request 1 → Proxy A
Request 2 → Proxy B
Request 3 → Proxy C
Request 4 → Proxy A (round-robin)
```

**Without rotation:**
```
Request 1 → Proxy A
Request 2 → Proxy A
Request 3 → Proxy A
Request 4 → Proxy A
```

**Use rotation when:**
- Avoiding rate limits (distribute load)
- Bypassing per-IP restrictions
- Scanning large ranges

**Don't rotate when:**
- Testing specific proxy
- Debugging proxy issues
- Single proxy required (authentication)

---

### `--proxy-test`
Test proxies before using them.

**Default:** Enabled (`true`)

```bash
# Default (test proxies)
origindive -d example.com --proxy-auto

# Skip testing (use all proxies, even broken ones)
origindive -d example.com --proxy-auto --proxy-test=false
```

**Testing process:**
```
1. Fetch proxies from sources (184 proxies)
2. Smart sampling (validate 175 proxies)
3. Test each proxy:
   ├─ Send request through proxy
   ├─ Try 6 IP check endpoints with fallback
   ├─ Verify we get different IP than our real IP
   └─ Accept if successful
4. Keep working proxies (13 working)
5. Use for scan
```

**When to disable:**
```bash
# Known-good proxy list
origindive -d example.com --proxy-file working-proxies.txt --proxy-test=false

# Very fast scans (skip validation overhead)
origindive -d example.com --proxy-auto --proxy-test=false
# ⚠️ Warning: May use broken proxies
```

---

## WAF/CDN Filtering

### `--skip-waf`
Skip scanning known CDN/WAF IP ranges.

```bash
# Enable WAF filtering (recommended for large scans)
origindive -d example.com -c 104.16.0.0/12 --skip-waf
```

**What it does:**
- Loads database of 108 CIDR ranges across 6 providers
- Checks each IP before scanning
- Skips IPs in known CDN/WAF ranges
- Drastically reduces scan time

**Providers filtered:**
1. **Cloudflare** - 15 ranges (104.16.0.0/12, 172.64.0.0/13, etc.)
2. **AWS CloudFront** - 44 ranges
3. **Fastly** - 18 ranges
4. **Akamai** - 12 ranges
5. **Incapsula/Imperva** - 12 ranges
6. **Sucuri** - 7 ranges

**Performance impact:**
```bash
# Without --skip-waf
# Scan 104.16.0.0/12 = 1,048,576 IPs
# Time: ~29 hours at 10 req/s

# With --skip-waf
# Scan 104.16.0.0/12, skip 942,080 CDN IPs = 106,496 real IPs
# Time: ~3 hours at 10 req/s
# Savings: 90% faster!
```

**Use when:**
- Scanning large CIDR blocks (/16, /12, /8)
- Scanning ASNs of cloud providers
- Any scan with > 1000 IPs

**Example:**
```bash
# Scan Cloudflare ASN (2.7M IPs)
# ⚠️ Bad: Will take weeks
origindive -d example.com --asn AS13335

# ✅ Good: Skip Cloudflare's own ranges
origindive -d example.com --asn AS13335 --skip-waf
# Scans only non-Cloudflare IPs in AS13335
```

**Statistics:**
```
Scan complete!
  Scanned: 106,496 IPs
  Skipped: 942,080 IPs (89.8%)
    ├─ Cloudflare: 524,288 IPs
    ├─ AWS: 262,144 IPs
    ├─ Fastly: 131,072 IPs
    └─ Others: 24,576 IPs
```

---

### `--skip-providers <list>`
Skip specific CDN/WAF providers only.

```bash
# Skip only Cloudflare
origindive -d example.com -c 104.16.0.0/12 --skip-providers cloudflare

# Skip multiple providers
origindive -d example.com -c 0.0.0.0/8 --skip-providers cloudflare,aws-cloudfront,fastly

# Combine with --skip-waf (all providers)
origindive -d example.com -c 0.0.0.0/8 --skip-waf
```

**Provider IDs:**
- `cloudflare`
- `aws-cloudfront`
- `fastly`
- `akamai`
- `incapsula`
- `sucuri`

**Use when:**
- You know target uses specific CDN
- Fine-grained control over what to skip
- Testing specific provider ranges

**Example:**
```bash
# Target uses Cloudflare, but might use AWS for origin
# Skip Cloudflare, scan AWS ranges
origindive -d example.com --asn AS13335 --skip-providers cloudflare
```

---

### `--custom-waf <file>`
Load custom WAF/CDN IP ranges to skip.

```bash
# JSON format (same as data/waf_ranges.json)
origindive -d example.com -c 192.0.2.0/24 --custom-waf my-waf-ranges.json

# Plain text format (one CIDR per line)
origindive -d example.com -c 192.0.2.0/24 --custom-waf my-cidrs.txt
```

**JSON format:**
```json
[
  {
    "id": "my-custom-cdn",
    "name": "My Custom CDN",
    "ranges": [
      "203.0.113.0/24",
      "198.51.100.0/24"
    ]
  }
]
```

**Text format:**
```text
# My custom WAF ranges
203.0.113.0/24
198.51.100.0/24

# Another set
192.0.2.0/28
```

**Use when:**
- Your organization uses private CDN
- Additional ranges to skip beyond built-in list
- Testing custom firewall configurations

**Merging:**
```bash
# Custom ranges ADDED to default ranges
# Total ranges = 108 (default) + yours

# To REPLACE default ranges, use without --skip-waf
origindive -d example.com -c 192.0.2.0/24 --custom-waf only-mine.json
# (Still loads default DB, but only filters your custom ranges if not using --skip-waf)
```

---

### `--show-skipped`
Display IPs that were skipped due to WAF filtering.

```bash
# Show what gets skipped
origindive -d example.com -c 104.16.0.0/20 --skip-waf --show-skipped
```

**Output:**
```
[SKIP] 104.16.0.1 (Cloudflare)
[SKIP] 104.16.0.2 (Cloudflare)
[SKIP] 104.16.0.3 (Cloudflare)
...
[+] 104.16.15.10 --> 200 OK (123ms)
[SKIP] 104.16.16.1 (Cloudflare)
...

Summary:
  Scanned: 150 IPs
  Skipped: 3,946 IPs
    └─ Cloudflare: 3,946 IPs
```

**Use when:**
- Debugging WAF filter behavior
- Verifying custom ranges work
- Understanding what's being filtered

**Warning:**
- Very verbose output for large scans
- Don't use with `> 10K` IPs (output overload)

---

### `--no-waf-update`
Disable automatic WAF database updates.

**Default:** Auto-update every 7 days

```bash
# Disable auto-update
origindive -d example.com -c 192.0.2.0/24 --skip-waf --no-waf-update
```

**Update behavior:**
```
1. Check last update timestamp
2. If > 7 days old:
   ├─ Fetch latest ranges from Cloudflare API
   ├─ Fetch latest ranges from AWS API
   ├─ Fetch latest ranges from Fastly API
   └─ Update cached database
3. Use cached database for scan
```

**Update sources:**
- Cloudflare: https://www.cloudflare.com/ips-v4
- AWS: https://ip-ranges.amazonaws.com/ip-ranges.json
- Fastly: https://api.fastly.com/public-ip-list

**Manual update:**
```bash
# Force update now
origindive --update-waf
```

**Use `--no-waf-update` when:**
- Offline scans (no internet for API calls)
- Consistent results (don't change DB mid-scan)
- Testing with specific database version

**Cache location:**
- `~/.config/origindive/waf_ranges.json` (runtime)
- `data/waf_ranges.json` (bundled default)

---

## Passive Reconnaissance

### `--passive-sources <list>`
Specify which OSINT sources to query.

```bash
# All sources (default in --passive mode)
origindive -d example.com --passive

# Specific sources only
origindive -d example.com --passive --passive-sources ct,virustotal,shodan

# Free sources only (no API keys needed)
origindive -d example.com --passive --passive-sources ct,viewdns,dnsdumpster,wayback

# Premium sources (require API keys)
origindive -d example.com --passive --passive-sources shodan,censys,securitytrails
```

**Available sources:**
1. `ct` - Certificate Transparency (free, no key)
2. `dns` - DNS history (free, no key)
3. `shodan` - Shodan (requires API key)
4. `censys` - Censys (requires API token)
5. `securitytrails` - SecurityTrails (requires API key)
6. `virustotal` - VirusTotal (requires API key, free tier)
7. `viewdns` - ViewDNS (free, rate limited)
8. `dnsdumpster` - DNSDumpster (free, 1 req/2s)
9. `wayback` - Wayback Machine (free, no key)
10. `zoomeye` - ZoomEye (requires API key, credits)

**Default behavior:**
```bash
# Without --passive-sources: Uses ALL sources with valid API keys
origindive -d example.com --passive

# Skips sources with missing/invalid API keys
# Shows which sources were skipped
```

**Configuration:**
```yaml
# ~/.config/origindive/config.yaml
passive_sources:
  - ct
  - virustotal
  - shodan
  - wayback

shodan_keys:
  - "YOUR_SHODAN_KEY"
virustotal_key: "YOUR_VT_KEY"
```

See [PASSIVE_RECONNAISSANCE.md](PASSIVE_RECONNAISSANCE.md) for API key setup.

---

### `--min-confidence <score>`
Filter passive results by confidence score.

**Default:** 0.7 (70%)

```bash
# High confidence only
origindive -d example.com --passive --min-confidence 0.9

# Medium confidence
origindive -d example.com --passive --min-confidence 0.6

# All results (including low confidence)
origindive -d example.com --passive --min-confidence 0.0
```

**Confidence scoring (0.0 - 1.0):**

| Score | Meaning | Example |
|-------|---------|---------|
| 0.9+ | Very high | IP found in 3+ sources, recent A record |
| 0.7-0.9 | High | IP in 2 sources, verified in CT logs |
| 0.5-0.7 | Medium | IP in 1 source, historical record |
| 0.3-0.5 | Low | Old record, unverified |
| < 0.3 | Very low | Speculative, weak signal |

**Scoring factors:**
1. **Source reliability** - How trustworthy is the source?
2. **Data freshness** - How recent is the information?
3. **Record type** - A record > CNAME > Certificate
4. **Cross-verification** - Found in multiple sources?
5. **ASN consistency** - Expected network?
6. **Geographic consistency** - Expected location?
7. **Port validation** - Responds on expected ports?
8. **Response similarity** - Content matches domain?

**Example output:**
```bash
origindive -d example.com --passive --min-confidence 0.8

[PASSIVE] Shodan
  ├─ 192.0.2.10 (confidence: 0.95) ✓
  └─ 192.0.2.20 (confidence: 0.72) ✗ (below threshold)

[PASSIVE] Certificate Transparency
  ├─ 192.0.2.10 (confidence: 0.92) ✓
  └─ 192.0.2.30 (confidence: 0.65) ✗ (below threshold)

Discovered: 1 IP (filtered 2 low-confidence)
```

**Use when:**
- Large number of results, want only best
- Avoiding false positives
- Prioritizing quality over quantity

See [SCORING_ALGORITHMS.md](SCORING_ALGORITHMS.md) for detailed scoring.

---

## Output Configuration

### `-o, --output <file>`
Save results to file.

```bash
# Text output (default)
origindive -d example.com -c 192.0.2.0/24 -o results.txt

# JSON output
origindive -d example.com -c 192.0.2.0/24 -f json -o results.json

# CSV output
origindive -d example.com -c 192.0.2.0/24 -f csv -o results.csv

# Auto-generate filename (passive mode)
origindive -d example.com --passive
# Saves to: example.com-passive-2025-12-05_14-30-45.txt
```

**File handling:**
- Creates directories if needed
- Overwrites existing files
- Colors stripped from file output (even if terminal supports color)
- Progress bar NOT written to file

---

### `-f, --format <format>`
Output format.

**Default:** text

```bash
# Text (human-readable, colored)
origindive -d example.com -c 192.0.2.0/24 -f text

# JSON (machine-readable)
origindive -d example.com -c 192.0.2.0/24 -f json

# CSV (spreadsheet-compatible)
origindive -d example.com -c 192.0.2.0/24 -f csv
```

**Text format:**
```
[+] 192.0.2.10 --> 200 OK (123ms)
[+] 192.0.2.11 --> 200 OK (234ms)

Success: 2/256 IPs returned 200 OK
```

**JSON format:**
```json
{
  "target": "example.com",
  "success": [
    {
      "ip": "192.0.2.10",
      "status": 200,
      "message": "OK",
      "response_time": "123ms"
    }
  ],
  "summary": {
    "success_count": 2,
    "scanned_ips": 256
  }
}
```

**CSV format:**
```csv
IP,Status,Message,ResponseTime
192.0.2.10,200,OK,123ms
192.0.2.11,200,OK,234ms
```

---

### `-q, --quiet`
Suppress all output except results.

```bash
# Quiet mode
origindive -d example.com -c 192.0.2.0/24 -q
```

**Suppresses:**
- Banner
- Progress bar
- Status messages
- Statistics

**Outputs:**
- Results only (IP, status, time)
- Errors (to stderr)

**Use when:**
- Piping to other tools
- Batch processing
- Minimal output needed

---

### `-a, --show-all`
Show all responses (not just 200 OK).

```bash
# Show everything
origindive -d example.com -c 192.0.2.0/24 -a
```

**Without `-a` (default):**
```
[+] 192.0.2.10 --> 200 OK (123ms)
[+] 192.0.2.15 --> 200 OK (234ms)

Success: 2/256 IPs
```

**With `-a`:**
```
[+] 192.0.2.10 --> 200 OK (123ms)
[+] 192.0.2.11 --> 301 Moved Permanently (100ms)
[+] 192.0.2.12 --> 403 Forbidden (150ms)
[+] 192.0.2.13 --> 404 Not Found (120ms)
[+] 192.0.2.14 --> 500 Internal Server Error (200ms)
[+] 192.0.2.15 --> 200 OK (234ms)
[+] 192.0.2.16 --> Timeout
[+] 192.0.2.17 --> Connection refused

Success: 2/256 IPs
Redirects: 1/256 IPs
Client errors: 2/256 IPs
Server errors: 1/256 IPs
Timeouts: 1/256 IPs
```

**Use when:**
- Debugging scan issues
- Analyzing non-200 responses
- Finding redirect chains
- Identifying WAF signatures

---

### `--no-color`
Disable colored output.

```bash
# No colors
origindive -d example.com -c 192.0.2.0/24 --no-color
```

**Use when:**
- Terminal doesn't support colors
- Logging to file (colors already stripped)
- CI/CD pipelines
- Accessibility requirements

---

### `--no-progress`
Disable progress bar.

```bash
# No progress bar
origindive -d example.com -c 192.0.2.0/24 --no-progress
```

**Use when:**
- Logging output
- CI/CD pipelines (progress bar clutters logs)
- Piping output
- Slow terminals

---

## Utility Flags

### `-V, --version`
Show version information.

```bash
origindive --version
# Output: origindive v3.1.0
```

### `--update`
Check for and install updates.

```bash
origindive --update
```

**Process:**
1. Query GitHub API for latest release
2. Compare with current version
3. Download ZIP for current platform
4. Extract binary
5. Replace current binary
6. Create backup of old version

### `--update-waf`
Update WAF IP ranges database.

```bash
origindive --update-waf
```

### `--init-config`
Initialize global configuration file.

```bash
origindive --init-config
```

Creates `~/.config/origindive/config.yaml` with template.

### `--show-config`
Show global config file path.

```bash
origindive --show-config
# Output: /home/user/.config/origindive/config.yaml
```

### `--config <file>`
Load configuration from YAML file.

```bash
origindive --config scan-config.yaml
```

CLI flags override config file settings.

---

## Configuration File Example

`scan-config.yaml`:
```yaml
# Target
domain: "example.com"

# IP ranges
cidr: "192.0.2.0/24"

# Performance
workers: 20
timeout: "5s"
connect_timeout: "3s"

# HTTP
http_method: "GET"
user_agent: "chrome"
verify_content: true

# WAF filtering
skip_waf: true
skip_providers:
  - cloudflare
  - aws-cloudfront

# Proxy
proxy_auto: true
webshare_keys:
  - "YOUR_API_KEY"

# Passive
passive_sources:
  - ct
  - virustotal
  - shodan
min_confidence: 0.7

# Output
format: "json"
output_file: "results.json"
quiet: false
show_all: false
```

Usage:
```bash
origindive --config scan-config.yaml
```

---

## Quick Reference

### Common Workflows

**Basic scan:**
```bash
origindive -d example.com -c 192.0.2.0/24
```

**Fast scan with WAF filtering:**
```bash
origindive -d example.com --asn AS13335 --skip-waf -j 50
```

**Comprehensive discovery:**
```bash
origindive -d example.com --auto-scan -n /24 --verify
```

**Proxy scan:**
```bash
origindive -d example.com -c 192.0.2.0/24 --proxy-auto
```

**Export results:**
```bash
origindive -d example.com -c 192.0.2.0/24 -f json -o results.json
```

---

## See Also

- [README.md](../README.md) - Main documentation
- [PASSIVE_RECONNAISSANCE.md](PASSIVE_RECONNAISSANCE.md) - OSINT source details
- [PROXY_GUIDE.md](PROXY_GUIDE.md) - Proxy configuration
- [ASN_LOOKUP.md](ASN_LOOKUP.md) - ASN enumeration
- [SCORING_ALGORITHMS.md](SCORING_ALGORITHMS.md) - Confidence scoring
- [EXTERNAL_URLS.md](EXTERNAL_URLS.md) - API endpoints
