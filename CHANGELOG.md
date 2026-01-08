# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [3.2.4] - 2026-01-08

### Added
- `--input-scrape` flag: Scrape IPv4 addresses from a file and use as input
- **Module versioning**: Updated to `/v3` suffix (Go semantic import versioning)
  - All imports updated to `github.com/jhaxce/origindive/v3`
  - Ensures proper dependency management for v3.x releases
- **Comprehensive test suite improvements** (4 packages at 95%+ coverage)
  - **`pkg/passive/virustotal`**: 42.3% → 98.6% (+56.3%)
    - 37 test cases covering all code paths
    - Mock HTTP servers for API testing
    - `SearchSubdomains` function at 100% coverage
    - Tests: rate limiting, error handling, IPv6 filtering, subdomain resolution, context cancellation, timeouts
  - **`pkg/core`**: 96.9% → 99.0% (+2.1%)
    - 58 test cases for configuration, global config, errors, results
    - Tests: empty home directory, invalid YAML, MkdirAll errors, read/write errors, platform-specific code
    - All functions at 87.5%+ coverage (remaining gaps are OS-specific paths)
  - **`pkg/passive/scoring`**: 95.7% → 96.5% (+0.8%)
    - 36 test cases for confidence scoring algorithm
    - `performReverseDNS` at 100% coverage
    - Tests: ptr_record handling, metadata caching, DNS lookup paths, network scenarios
  - **`pkg/passive/subdomain`**: Maintained 100.0% coverage
- Edge case testing: empty DNS values, invalid URLs, read errors, partial failures
- Network-aware test design with `-short` flag support for CI/CD pipelines
- Overall project coverage: 50.7% → 50.9%

### Removed
- `--ic` / `--is` legacy Censys-specific input flag (replaced by `--input-scrape`)

---

## [3.2.1] - 2025-12-06

### Fixed
- Validation triggering on `--follow-redirect` instead of requiring both `--verify` and `--follow-redirect`
- Double progress bar issue during validation phase
- CIDR expansion to scan all IPs including network and broadcast addresses

### Changed
- Passive reconnaissance now respects `-t` timeout flag
- DNS subdomain enumeration timeout adjusted to `4 × timeout`

---

## [3.2.0] - 2025-12-05

### Added
- **Redirect chain following** (`--follow-redirect[=N]`): Follow HTTP redirects while preserving IP testing
- **False positive detection**: Post-scan Host header validation to identify shared hosting
- **Enhanced summary display**: Shows verified origins vs all 200 OK responses
- Automatic output file generation with timestamped filenames
- `--silent-errors` flag: Suppress passive source API warnings
- Censys Organization ID prompt in `--init-config`
- Domain WAF/CDN detection in banner

### Changed
- Result output order reversed (200 OK now appears near summary)
- All 9 passive sources enabled by default
- Censys API uses tokens instead of ID/Secret pairs

### Fixed
- `.gitignore` pattern for binary exclusion
- Auto mode output formatting

---

## [3.1.0] - 2025-12-04

### Added
- **Passive reconnaissance** with 9 OSINT sources:
  - Certificate Transparency (crt.sh)
  - SecurityTrails, VirusTotal, Shodan, Censys
  - ViewDNS, DNSDumpster, Wayback Machine, ZoomEye
- **Confidence scoring system** (8-factor algorithm, 94.8% test coverage)
- **ASN lookup** (`--asn AS4775,AS9299`) with permanent caching
- **Global configuration** (`~/.config/origindive/config.yaml`)
- **Country-aware proxy fetching** (auto-detect via Cloudflare CDN trace)
- **Webshare.io integration** (free 10-proxy plan)
- **Multi-endpoint proxy validation** (6 fallback services)
- **User agent presets** (`-A chrome`, `-A random`, etc.)
- **Response verification** (`--verify`, `--filter-unique`)

### Changed
- Proxy validation moved to unified `ValidateProxy()` function
- Removed GitHub proxy sources (unreliable)
- Fixed golint warnings

---

## [3.0.0] - 2025-12-03

### Added
- **WAF/CDN IP filtering**: Auto-skip Cloudflare, AWS CloudFront, Fastly, Akamai, Incapsula, Sucuri (108 ranges)
- **Auto-update WAF ranges** from official provider APIs
- **Modular architecture**: Separated packages (core, scanner, waf, ip, output, passive)
- **YAML configuration file** support (`--config config.yaml`)
- **Multi-format output**: Text, JSON, CSV
- **Self-update** (`--update`)

### Changed
- **BREAKING**: Binary renamed from `originfind` to `origindive`
- **BREAKING**: Module path changed to `github.com/jhaxce/origindive/v3`
- **BREAKING**: Minimum Go version raised to 1.23
- Complete rewrite of core scanning engine

---

## [2.6.1] - 2025-12-03

### Added
- Auto-update feature (`--check-update`, `--update`)
- GitHub Actions release workflow (multi-platform builds)

---

## [2.6.0] - 2025-12-02

### Added
- Real-time progress bar with ETA
- `--no-progress` and `--no-ua` flags

---

## [2.5.0] - 2025-12-02

### Added
- CIDR mask application (`-i <file> -n /24`)
- Comprehensive inline code documentation

---

## [2.4.0] - 2025-12-02

### Added
- Full colored terminal output (WSL/Kali compatible)

### Fixed
- Colors not displaying in WSL/Kali environments

---

## [2.3.0] - 2025-12-02

### Added
- Positional argument support (`originfind <domain> <start_ip> <end_ip>`)
- Dynamic version in User-Agent header

---

## [2.2.0] - 2025-12-01

### Added
- Input file parsing (`-i` flag)
- Comment support in input files

---

## [2.1.0] - 2025-12-01

### Added
- CIDR notation support with automatic subnet expansion

---

## [2.0.0] - 2025-12-01

### Added
- Comprehensive documentation and branding
- MIT License

---

## [1.5.0] - 2025-12-01

### Added
- Multi-threaded scanning with worker pool
- Configurable timeouts and custom headers

---

## [1.0.0] - 2025-12-01

### Added
- Initial release
- Basic IP range scanning with Host header manipulation
- HTTP request functionality
- Success/failure reporting

---

[Unreleased]: https://github.com/jhaxce/origindive/compare/v3.2.1...HEAD
[3.2.1]: https://github.com/jhaxce/origindive/compare/v3.2.0...v3.2.1
[3.2.0]: https://github.com/jhaxce/origindive/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/jhaxce/origindive/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/jhaxce/origindive/compare/v2.6.1...v3.0.0
[2.6.1]: https://github.com/jhaxce/origindive/compare/v2.6.0...v2.6.1
[2.6.0]: https://github.com/jhaxce/origindive/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/jhaxce/origindive/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/jhaxce/origindive/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/jhaxce/origindive/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/jhaxce/origindive/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/jhaxce/origindive/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/jhaxce/origindive/compare/v1.5.0...v2.0.0
[1.5.0]: https://github.com/jhaxce/origindive/compare/v1.0.0...v1.5.0
[1.0.0]: https://github.com/jhaxce/origindive/releases/tag/v1.0.0
