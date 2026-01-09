<div align="center">

# origindive

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/origindive_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="images/origindive_light.png">
  <img alt="origindive ascii title" src="images/origindive_light.png">
</picture

**Dive deep to discover origin servers** - A powerful security analysis tool for discovering real origin server IPs hidden behind CDN/WAF services.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org/)
[![Release](https://img.shields.io/github/v/release/jhaxce/origindive)](https://github.com/jhaxce/origindive/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/jhaxce/origindive)](https://goreportcard.com/report/github.com/jhaxce/origindive)
[![codecov](https://codecov.io/gh/jhaxce/origindive/branch/main/graph/badge.svg)](https://codecov.io/gh/jhaxce/origindive)
[![Go Reference](https://pkg.go.dev/badge/github.com/jhaxce/origindive.svg)](https://pkg.go.dev/github.com/jhaxce/origindive)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fjhaxce%2Forigindive.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fjhaxce%2Forigindive?ref=badge_shield)

</div>

## Overview

origindive helps security researchers discover real IP addresses of web servers protected by CDN/WAF services (Cloudflare, AWS CloudFront, etc.). It works by sending HTTP requests directly to IP addresses with your target domain in the Host header.

**Scan Modes:**
- **Auto** (default): Passive reconnaissance → Active scanning
- **Passive**: OSINT discovery only (no HTTP requests)
- **Active**: Direct IP range scanning

## Installation

```bash
# Download pre-built binary
curl -L https://github.com/jhaxce/origindive/releases/latest/download/origindive-linux-amd64.tar.gz | tar xz
sudo mv origindive /usr/local/bin/

# Or build from source
git clone https://github.com/jhaxce/origindive.git && cd origindive
go build -o origindive cmd/origindive/main.go

# Or install with Go
go install github.com/jhaxce/origindive/cmd/origindive@latest
```

**Requirements:** Go 1.23+

## Quick Start

```bash
# Auto-scan mode (passive + active)
origindive -d example.com

# Scan specific CIDR with WAF filtering
origindive -d example.com -n 192.168.1.0/24 --skip-waf

# Scan ASN ranges with redirect following
origindive -d example.com --asn AS4775 --skip-waf --follow-redirect

# Passive reconnaissance only
origindive -d example.com --passive -o discovered_ips.txt

# Scan from file with verification
origindive -d example.com -i ips.txt --verify --filter-unique
```

## Key Features

| Feature | Description |
|---------|-------------|
| **WAF/CDN Filtering** | Auto-skip Cloudflare, AWS, Fastly, Akamai, etc. (108+ ranges) |
| **9 OSINT Sources** | CT logs, Shodan, Censys, VirusTotal, SecurityTrails, ViewDNS, DNSDumpster, Wayback, ZoomEye |
| **ASN Lookup** | Fetch IP ranges by ASN (`--asn AS4775,AS9299`) |
| **Smart Redirects** | Follow redirects with false positive detection |
| **Proxy Support** | HTTP/SOCKS5, auto-fetch public proxies, rotation |
| **Multi-Format Output** | Text, JSON, CSV |

## Command Reference

### Target Options
| Flag | Description |
|------|-------------|
| `-d, --domain` | Target domain (required) |
| `-s, --start-ip` / `-e, --end-ip` | IP range |
| `-n, --expand-netmask` | CIDR or mask for passive expansion |
| `-c, --cidr` | CIDR notation (e.g., `192.168.1.0/24`) |
| `-i, --input` | Input file with IPs/CIDRs |
| `--asn` | ASN lookup (e.g., `AS4775` or comma-separated) |
| `--input-scrape` | Scrape IPs from file and use as input |

### Performance
| Flag | Description |
|------|-------------|
| `-j, --threads` | Parallel workers (default: 10) |
| `-t, --timeout` | HTTP timeout in seconds (default: 5) |
| `--connect-timeout` | TCP connect timeout (default: 3) |

### WAF Filtering
| Flag | Description |
|------|-------------|
| `--skip-waf` | Skip known WAF/CDN IPs |
| `--skip-providers` | Skip specific providers (comma-separated) |
| `--custom-waf` | Custom WAF ranges file |
| `--show-skipped` | Display skipped IPs |

### HTTP Options
| Flag | Description |
|------|-------------|
| `-m, --method` | HTTP method (default: GET) |
| `-H, --header` | Custom header |
| `-A, --user-agent` | User-Agent: `random`, `chrome`, `firefox`, etc. |
| `--follow-redirect[=N]` | Follow redirects (default max: 10) |
| `--verify` | Extract title and hash response body |
| `--filter-unique` | Show only unique content (requires `--verify`) |

### Proxy
| Flag | Description |
|------|-------------|
| `-P, --proxy` | Proxy URL (`http://` or `socks5://`) |
| `--proxy-auto` | Auto-fetch from public lists |
| `--proxy-rotate` | Rotate through proxy list |

### Passive Mode
| Flag | Description |
|------|-------------|
| `--passive` | Passive reconnaissance only |
| `--auto-scan` | Passive then active scan |
| `--passive-sources` | Comma-separated sources |
| `--min-confidence` | Minimum confidence score (0.0-1.0) |

### Output
| Flag | Description |
|------|-------------|
| `-o, --output` | Output file (use `-o` alone for auto-name) |
| `-f, --format` | Format: `text`, `json`, `csv` |
| `-q, --quiet` | Minimal output |
| `-a, --show-all` | Show all responses |

### System
| Flag | Description |
|------|-------------|
| `--config` | YAML config file |
| `--update` | Check and install updates |
| `--init-config` | Initialize global config |
| `-V, --version` | Show version |

## Configuration

Create `config.yaml`:

```yaml
domain: "example.com"
cidr: "192.168.1.0/24"
skip_waf: true
workers: 20
timeout: "5s"
format: "json"
output_file: "results.json"
```

```bash
origindive --config config.yaml
```

## Response Verification

Identify real origin servers among many 200 OK responses:

```bash
# Show title and content hash
origindive -d example.com --asn AS18233 --skip-waf --verify

# Filter to unique responses only
origindive -d example.com -i ips.txt --verify --filter-unique
```

**Output:**
```
[+] 192.0.2.10 --> 200 OK (331ms) | "Default Apache Page" [e2dd2d7e]
[+] 192.0.2.50 --> 200 OK (518ms) | "Example Corporation" [f0d6e49d] ← UNIQUE
```

## Troubleshooting

**Getting 0 results?** Server may be rate-limiting:
```bash
# Reduce workers and increase timeout
origindive -d example.com -i ips.txt -j 5 -t 10
```

**Too many false positives with redirects?**
```bash
# Enable validation
origindive -d example.com -i ips.txt --follow-redirect --verify
```

## Testing & Quality

**origindive** maintains production-grade test coverage for critical packages:

| Package | Coverage | Status |
|---------|----------|--------|
| **Core Packages** | | |
| `pkg/core` | 99.0% | ✅ Excellent |
| `pkg/passive/virustotal` | 98.6% | ✅ Excellent |
| `pkg/passive/scoring` | 96.5% | ✅ Excellent |
| `pkg/passive/subdomain` | 100.0% | ✅ Perfect |
| **Overall Project** | 50.9% | 🟢 Good |

**Run tests:**
```bash
# All tests with coverage
go test ./... -cover

# Skip network-dependent tests
go test ./... -short -cover

# Generate HTML coverage report
go test -coverprofile=coverage.txt ./...
go tool cover -html=coverage.txt
```

**Test highlights:**
- 37 comprehensive test cases for VirusTotal integration (mock servers, rate limiting, error handling)
- 58 test cases for configuration management (YAML parsing, validation, platform-specific paths)
- 36 test cases for confidence scoring algorithm (DNS lookups, metadata caching)
- Network-aware test design with `-short` flag support
- Mock HTTP servers for API testing without external dependencies

## Legal Disclaimer

**Only scan systems you are authorized to test.** Unauthorized scanning may be illegal. The authors are not responsible for misuse.

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE).

---

**Made with 💖 by [jhaxce](https://github.com/jhaxce)**
