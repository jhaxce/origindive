# Copilot Instructions for origindive

## Repository Overview

**origindive** v3.1.0 is a security research tool for discovering origin server IPs hidden behind CDN/WAF services. Combines active HTTP scanning with intelligent WAF filtering and passive reconnaissance via 9 intelligence sources.

**Size**: ~3,500 lines across 30+ files in modular architecture  
**Language**: Go 1.23+  
**Module**: `github.com/jhaxce/origindive/v3`  
**Dependencies**: `gopkg.in/yaml.v3` (config), `github.com/spf13/pflag` (GNU-style flags)  
**Binary**: ~7 MB optimized  
**Status**: ✅ **PRODUCTION READY** - Active scanning + 9 passive sources implemented

## CRITICAL: Gitignore Permissions for Testing

**⚠️ IMPORTANT**: Copilot has explicit permission to read/write files listed in `.gitignore` for testing purposes.

**Coverage files are gitignored but essential for development**:
- `coverage.txt` - Primary coverage report
- `*.coverprofile` - Package-specific coverage (e.g., `scanner.coverprofile`, `waf.coverprofile`)
- `*_cov.txt` - Temporary coverage files
- `cov`, `corecov`, `profile.cov`, `core_coverage` - Legacy coverage files

**Usage**: When running tests with coverage, freely create and read these ignored files. Clean them up after use with:
```powershell
Remove-Item *.coverprofile, *_cov.txt -ErrorAction SilentlyContinue
```

**Workaround for Go 1.25+ bug**: Use absolute paths for coverage files:
```powershell
go test "-coverprofile=d:\CTF\Git\origindive\coverage.txt" ./...
```

## Critical Build & Validation

### ⚠️ CURRENT STATE - READ FIRST
- ✅ v3.1.0 **FULLY FUNCTIONAL** - active scanner + 9 passive intelligence sources
- ✅ All Go files compile successfully
- ✅ **6/9 passive sources working** (SecurityTrails, VirusTotal, Wayback, ViewDNS, DNSDumpster, ZoomEye)
- ⚠️ **3/9 sources require premium** (Shodan, Censys - membership needed; CT - service issues)
- ✅ **COMPREHENSIVE TEST SUITE** - 32 test files covering core packages
- ✅ **Test Coverage**: Core package at 96.9% (from 70.8%), overall improving
- ✅ **All test files follow standard `*_test.go` naming** (no `*_coverage_test.go` or `*_integration_test.go`)

### Build Commands (VALIDATED)

**✅ Build all packages** (works, exit code 0, <1s on modern hardware):
```powershell
go build -v ./...
```
Output: Silent (no output means success). Compiles all 8 packages.

**✅ Build main binary** (works, creates 9.4 MB executable):
```powershell
go build -o origindive.exe cmd/origindive/main.go
```
Output: `origindive.exe` in current directory (9,363,456 bytes).

**✅ Build optimized binary** (works, creates 6.6 MB executable, **RECOMMENDED**):
```powershell
go build -ldflags="-s -w" -o origindive.exe cmd/origindive/main.go
```
Output: `origindive.exe` (6,930,432 bytes). Strips debug symbols and DWARF data.

**✅ Run tests** (works, 32 test files):
```powershell
go test ./...
```
Output: Test results for all packages with coverage information

**✅ Generate coverage report** (save to coverage.txt):
```powershell
go test -coverprofile=coverage.txt ./...
go tool cover -func=coverage.txt
```
Output: Detailed per-function coverage statistics in `coverage.txt`

**✅ Vet code** (works, exit code 0):
```powershell
go vet ./...
```
Output: Silent (no output means no issues found).

**✅ Format code** (ALWAYS run before commit):
```powershell
go fmt ./...
```
Output: Lists paths of formatted files (or silent if no changes).

### GitHub Actions Workflow
Location: `.github/workflows/release.yml`  
Trigger: Push tags matching `v*` (e.g., `v3.0.0`, `v3.1.0`)  
Build command: `go build -ldflags="-s -w" -o <output> cmd/origindive/main.go`  
Platforms: windows/linux/darwin × amd64/arm64 (6 binaries total)  
Output: ZIP packages with binary, LICENSE, README.md, CHANGELOG.md  
Release: Automatic GitHub Release with download links and checksums

## Architecture & File Layout

### Directory Structure (Complete)
```
origindive/
├── cmd/origindive/          # ✅ CLI entry point (1 file, ~1,250 LOC)
│   └── main.go             # Flag parsing, config loading, scanner + passive orchestration
├── pkg/                     # ✅ Public packages (25+ files, ~3,500 LOC)
│   ├── core/               # Config, results, errors (4 files)
│   │   ├── config.go       # YAML config loading, CLI merging, validation
│   │   ├── globalconfig.go # Global config from ~/.config/origindive/
│   │   ├── errors.go       # Error definitions
│   │   └── result.go       # ScanResult, IPResult, PassiveIP types
│   ├── waf/                # WAF filtering (4 files)
│   │   ├── filter.go       # Thread-safe IP filtering with atomic counters
│   │   ├── providers.go    # Load/save WAF database, provider lookup
│   │   ├── ranges.go       # RangeSet for IP lookups, custom range loading
│   │   └── updater.go      # Auto-update from Cloudflare/AWS/Fastly APIs
│   ├── ip/                 # IP utilities (4 files)
│   │   ├── file.go         # Parse input files (IPs/CIDRs/ranges, comments)
│   │   ├── iterator.go     # Channel-based concurrent IP iteration
│   │   ├── parser.go       # IP/CIDR parsing, uint32 conversion
│   │   └── validator.go    # Domain/IP/CIDR validation, private IP detection
│   ├── output/             # Output system (3 files)
│   │   ├── formatter.go    # Text/JSON/CSV formatters with color support
│   │   ├── progress.go     # Real-time progress bar with ETA
│   │   └── writer.go       # File/console output, color stripping
│   ├── scanner/            # HTTP scanner (1 file)
│   │   └── scanner.go      # Worker pool, WAF integration, result categorization
│   ├── update/             # Self-update (1 file)
│   │   └── updater.go      # GitHub release API, asset download, binary replacement
│   └── passive/            # ✅ OSINT modules (9 sources implemented)
│       ├── censys/         # ✅ Censys v3 Global Search API (POST, requires org ID)
│       ├── ct/             # ✅ Certificate Transparency via crt.sh JSON
│       ├── dnsdumpster/    # ✅ DNSDumpster API (FREE tier)
│       ├── dns/            # DNS passive module (placeholder)
│       ├── scoring/        # Confidence scoring (placeholder)
│       ├── securitytrails/ # ✅ SecurityTrails API (premium - working)
│       ├── shodan/         # ✅ Shodan API (requires membership for hostname filter)
│       ├── subdomain/      # Subdomain enumeration (placeholder)
│       ├── viewdns/        # ✅ ViewDNS API (working)
│       ├── virustotal/     # ✅ VirusTotal API (FREE tier - working)
│       ├── wayback/        # ✅ Wayback Machine API (FREE - working)
│       └── zoomeye/        # ✅ ZoomEye v2 POST API (needs credits)
├── internal/               # ✅ Private packages (2 files)
│   ├── colors/             # ANSI color detection
│   │   └── colors.go
│   └── version/            # Version constants (v3.1.0)
│       └── version.go
├── data/                   # ✅ JSON databases (2 files)
│   ├── waf_ranges.json    # 108 CIDR ranges for 6 providers
│   └── waf_sources.json   # Auto-update configuration (API endpoints)
├── configs/                # ✅ Example config (1 file)
│   └── example.yaml       # Complete config with all options documented
├── scripts/                # ✅ Build scripts (1 file)
│   └── build.ps1          # PowerShell build automation
├── .github/                # ✅ GitHub config (2 files)
│   ├── workflows/
│   │   └── release.yml    # GitHub Actions release workflow
│   └── copilot-instructions.md  # This file
├── go.mod                  # Module definition (Go 1.23, yaml.v3 + pflag)
├── go.sum                  # Dependency checksums
├── .gitignore              # Git ignore patterns
├── LICENSE                 # MIT License
├── README.md               # User documentation (installation, usage, features)
├── CHANGELOG.md            # Release notes (Keep a Changelog format)
└── STATUS.md               # Development status (current state, completed features)
```

**Total**: 30+ Go files, ~3,500 lines of code (excluding comments/blank lines)

### Package Dependency Graph
```
cmd/origindive/main.go
├── pkg/core (config, results, errors, globalconfig)
├── pkg/scanner (HTTP scanning)
│   ├── pkg/core (results)
│   ├── pkg/waf (filtering)
│   └── pkg/ip (iteration)
├── pkg/waf (filtering)
│   └── pkg/core (errors)
├── pkg/ip (parsing, validation)
│   └── pkg/core (errors)
├── pkg/output (formatting, writing, progress)
│   └── pkg/core (results)
├── pkg/update (self-update)
│   └── internal/version
├── pkg/passive/* (9 intelligence sources)
│   └── pkg/core (errors, results - no cross-dependencies)
└── internal/version
    └── internal/colors
```

**Key Design Rules**:
- `pkg/core` has NO dependencies on other packages (shared types only)
- Never import from `cmd/` (prevents circular dependencies)
- `internal/` packages can only be imported by this module

### Key Files Deep Dive

**`cmd/origindive/main.go`** (294 lines):
- **Purpose**: CLI entry point, flag parsing, orchestration
- **Flags**: 50+ flags with GNU-style convention (pflag)
  - Short flags: `-d`, `-n`, `-j` (single dash)
  - Long flags: `--domain`, `--cidr`, `--threads` (double dash)
- **Features**:
  - YAML config loading via `--config` (overridden by CLI flags)
  - Self-update via `--update` flag
  - Input file parsing via `-i` flag (IPs/CIDRs/ranges with comments)
  - WAF filter initialization (with custom ranges via `--custom-waf`)
  - Scanner setup and execution
  - Progress bar and output formatting
  - Exit codes: 0 (success/results), 1 (no results/error)
- **Tested**: ✅ Compiles, runs, help output correct

**`pkg/core/config.go`** (231 lines):
- **Purpose**: Configuration management with YAML support
- **Key Functions**:
  - `DefaultConfig()` - Returns config with sensible defaults
  - `LoadFromFile(path)` - Parse YAML config file (uses `gopkg.in/yaml.v3`)
  - `MergeWithCLI(cliConfig)` - CLI flags override file settings
  - `Validate()` - Check config validity, warn on large CIDRs
- **Features**:
  - ScanMode: passive/active/auto
  - OutputFormat: text/json/csv
  - All CLI flags mapped to struct fields
  - YAML tags for file loading
- **Tested**: ✅ YAML loading works, merging works

**`pkg/scanner/scanner.go`** (291 lines):
- **Purpose**: HTTP-based origin IP scanner with worker pool
- **Key Functions**:
  - `NewScanner(config, wafFilter)` - Create scanner instance
  - `Scan(ctx, ipIterator)` - Run scan with concurrency
- **Features**:
  - Worker pool pattern (default 20 workers, configurable)
  - Context-aware cancellation (Ctrl+C support)
  - WAF filter integration (skip CDN/WAF IPs)
  - HTTP client with custom timeout (default 5s)
  - Host header injection (for testing)
  - Result categorization (200, 3xx, 4xx, 5xx, timeout, error)
  - Response time tracking (as string, e.g., "123ms")
  - Atomic counters for thread safety (tested, scanned, filtered)
- **Tested**: ✅ Scans work, WAF filtering works, results categorized correctly

**`pkg/waf/filter.go`** (147 lines):
- **Purpose**: Thread-safe WAF IP filtering
- **Key Functions**:
  - `NewFilter(rangeSet, providers)` - Create filter
  - `ShouldSkip(ipUint32)` - Returns (skip bool, providerID string)
  - `Stats()` - Get filter statistics (total skipped, by provider)
- **Features**:
  - Atomic counters (`sync/atomic`, no mutexes)
  - Per-provider statistics tracking
  - O(n) lookup across all ranges (n = 108, fast enough)
- **Tested**: ✅ Filtering works, stats accurate

**`pkg/waf/ranges.go`** (196 lines):
- **Purpose**: IP range management and custom range loading
- **Key Functions**:
  - `NewRangeSet(ranges)` - Create efficient range set
  - `Contains(ipUint32)` - Check if IP is in any range
  - `FindProvider(ipUint32)` - Get provider ID for IP
  - `LoadCustomRanges(path)` - Load custom CIDR file (JSON or text)
- **Formats Supported**:
  - JSON: Same format as `data/waf_ranges.json`
  - Text: One CIDR per line, `#` comments allowed
- **Tested**: ✅ Range lookups work, custom file loading works

**`pkg/ip/file.go`** (89 lines):
- **Purpose**: Parse IP input files
- **Key Functions**:
  - `ParseFile(path)` - Returns `[]IPRange`, error
- **Formats Supported**:
  - Single IPs: `192.168.1.1`
  - CIDR ranges: `192.168.1.0/24`
  - IP ranges: `192.168.1.1-192.168.1.254`
  - Comments: Lines starting with `#`
  - Blank lines: Ignored
- **Error Handling**: Reports line numbers for invalid entries
- **Tested**: ✅ Parses all formats, handles comments/blanks

**`pkg/update/updater.go`** (376 lines):
- **Purpose**: Self-update mechanism via GitHub releases
- **Key Functions**:
  - `CheckForUpdate(currentVersion)` - Query GitHub API for latest release
  - `DownloadUpdate(release, platform)` - Download ZIP for current OS/arch
  - `ExtractBinary(zipPath, platform)` - Extract binary from ZIP
  - `ReplaceCurrentBinary(newBinaryPath)` - Atomic replacement with backup
- **Features**:
  - Semantic version comparison (v3.0.0 < v3.1.0)
  - Platform detection (windows/linux/darwin, amd64/arm64)
  - ZIP extraction (stdlib only, no external deps)
  - Atomic file replacement (rename old → backup, rename new → current)
  - Rollback on failure
- **Tested**: ✅ Version check works (will work once v3.0.0 released)

**`data/waf_ranges.json`** (161 lines):
- **Purpose**: Default WAF/CDN IP ranges database
- **Format**: JSON array of provider objects
- **Contents**:
  - Cloudflare: 15 IPv4 ranges
  - AWS CloudFront: 44 IPv4 ranges
  - Fastly: 18 IPv4 ranges
  - Akamai: 12 IPv4 ranges
  - Incapsula: 12 IPv4 ranges
  - Sucuri: 7 IPv4 ranges
- **Total**: 108 CIDR ranges
- **Updateable**: Via `pkg/waf/updater.go` from provider APIs

## Code Style & Patterns (MANDATORY)

### Import Order (STRICTLY ENFORCED)
```go
import (
    "context"        // 1. Standard library (alphabetical)
    "fmt"
    "net"
    
    "github.com/spf13/pflag"  // 2. Third-party (alphabetical)
    "gopkg.in/yaml.v3"
    
    "github.com/jhaxce/origindive/internal/version"  // 3. Internal (alphabetical)
    "github.com/jhaxce/origindive/pkg/core"
)
```

### Error Handling (REQUIRED)
```go
// Define sentinel errors in pkg/core/errors.go
var ErrInvalidIP = errors.New("invalid IP address")
var ErrInvalidConfig = errors.New("invalid configuration")

// Always wrap with context using %w
if err != nil {
    return fmt.Errorf("failed to parse CIDR %s: %w", cidr, err)
}

// Check nil pointers before use
if obj == nil {
    return fmt.Errorf("object cannot be nil")
}

// Use errors.Is for sentinel error checks
if errors.Is(err, ErrInvalidIP) {
    // Handle specific error
}
```

### Concurrency Patterns (CRITICAL)
```go
// Use atomic for counters (NOT mutex, NOT ++)
var counter uint64
atomic.AddUint64(&counter, 1)
value := atomic.LoadUint64(&counter)

// Buffer channels to prevent blocking (size = workers * 2)
jobs := make(chan uint32, workerCount*2)
results := make(chan Result, workerCount*2)

// Always use context for cancellation
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Wait groups for worker synchronization
var wg sync.WaitGroup
wg.Add(workerCount)
for i := 0; i < workerCount; i++ {
    go func() {
        defer wg.Done()
        // Worker logic
    }()
}
wg.Wait()
```

### IP Operations (PERFORMANCE)
```go
// Convert net.IP to uint32 for efficiency (NOT net.IP in loops)
func ToUint32(ip net.IP) (uint32, error) {
    ip = ip.To4()
    if ip == nil {
        return 0, ErrInvalidIP
    }
    return uint32(ip[0])<<24 | uint32(ip[1])<<16 | 
           uint32(ip[2])<<8 | uint32(ip[3]), nil
}

// Convert uint32 back to net.IP when needed
func FromUint32(ipInt uint32) net.IP {
    return net.IPv4(
        byte(ipInt>>24),
        byte(ipInt>>16),
        byte(ipInt>>8),
        byte(ipInt),
    )
}

// Iterate IPs as uint32, convert back only for output
for ipInt := start; ipInt <= end; ipInt++ {
    // Process ipInt (fast)
    ip := FromUint32(ipInt)  // Convert only when needed
}
```

### CIDR Handling (EDGE CASES)
```go
// Handle /31 and /32 specially (RFC 3021)
ones, _ := network.Mask.Size()
if ones < 31 {
    // Standard network: skip network and broadcast addresses
    first = networkInt + 1
    last = broadcastInt - 1
} else if ones == 31 {
    // Point-to-point link: both IPs usable
    first = networkInt
    last = networkInt + 1
} else {  // ones == 32
    // Single host
    first = networkInt
    last = networkInt
}
```

## Common Issues & Solutions

### Issue: Build fails with "package ... is not in GOROOT"
**Cause**: Module path mismatch or missing `go.mod`  
**Solution**: Ensure `go.mod` exists with correct module path:
```
module github.com/jhaxce/origindive/v3
go 1.23
require gopkg.in/yaml.v3 v3.0.1
```
Run `go mod download` to fetch dependencies.

### Issue: Import cycle errors
**Cause**: Circular dependencies between packages  
**Solution**:
- Move shared types to `pkg/core/` (config, results, errors)
- Never import from `cmd/` in any package
- Use interfaces to break cycles (e.g., `pkg/scanner` depends on interface, not concrete type)

### Issue: Race conditions in counters
**Cause**: Using `++` or `+=` instead of atomic operations  
**Solution**: ALWAYS use `sync/atomic` for concurrent access:
```go
atomic.AddUint64(&counter, 1)  // NOT counter++
value := atomic.LoadUint64(&counter)  // NOT value = counter
```
Run `go build -race` to detect races (not available on all platforms).

### Issue: Memory allocations in IP iteration
**Cause**: Using `net.IP` in tight loops  
**Solution**: Convert to `uint32` once, iterate as integers:
```go
// Bad (allocates on every iteration)
for ip := start; !ip.Equal(end); ip = nextIP(ip) {
    process(ip)
}

// Good (no allocations)
startInt, _ := ToUint32(start)
endInt, _ := ToUint32(end)
for ipInt := startInt; ipInt <= endInt; ipInt++ {
    process(ipInt)
}
```

### Issue: Large CIDR scans are slow
**Cause**: Too few workers or WAF filtering disabled  
**Solution**:
- Enable WAF filtering: `--skip-waf` (skips 108 ranges)
- Increase workers: `-j 50` (default 20)
- Use custom WAF ranges: `--custom-waf myranges.txt`

### Issue: Binary size is 9.4 MB
**Cause**: Debug symbols and DWARF data included by default  
**Solution**: Use `-ldflags="-s -w"` for 6.6 MB binary (30% smaller):
```powershell
go build -ldflags="-s -w" -o origindive.exe cmd/origindive/main.go
```
This strips symbols (`-s`) and DWARF debug info (`-w`).

## Validation Checklist (Before Commit)

Run these commands in order:

1. **Format code** (shows formatted files):
   ```powershell
   go fmt ./...
   ```

2. **Vet code** (must be silent):
   ```powershell
   go vet ./...
   ```

3. **Build all packages** (must exit 0):
   ```powershell
   go build -v ./...
   ```

4. **Build binary** (must create executable):
   ```powershell
   go build -ldflags="-s -w" -o origindive.exe cmd/origindive/main.go
   ```

5. **Check binary size** (should be ~6.6 MB):
   ```powershell
   (Get-Item origindive.exe).Length / 1MB
   ```

6. **Manual checks**:
   - [ ] Import order: stdlib → third-party → internal
   - [ ] All exported functions/types have godoc comments
   - [ ] Error handling uses `fmt.Errorf` with `%w` wrapping
   - [ ] Concurrent code uses `sync/atomic` for counters
   - [ ] No new external dependencies added (only yaml.v3 and pflag allowed)
   - [ ] Updated `CHANGELOG.md` if adding features
   - [ ] Updated `STATUS.md` if changing implementation status

## Known Limitations

1. **No unit tests** - All packages report `[no test files]`
   - Future work: Add tests for core logic (IP parsing, WAF filtering, config loading)

2. **Passive sources require API keys** - 9 sources implemented, 6 working
   - SecurityTrails: Premium working (53 IPs from test)
   - VirusTotal: FREE tier working (6 IPs, 4 req/min)
   - Wayback Machine: FREE, no key needed (4 IPs)
   - ViewDNS: Working (4 IPs)
   - DNSDumpster: FREE tier working (4 IPs, 1 req/2s)
   - ZoomEye: v2 POST API working (needs credits)
   - Certificate Transparency: crt.sh JSON endpoint (service timeout issues)
   - Shodan: Requires membership for hostname search (FREE = IP lookup only)
   - Censys: v3 API requires org ID (FREE = Web UI only)

3. **No rate limiting** - Scanner can overwhelm targets with high worker counts
   - Workaround: Use `-j` flag to limit workers (default 20)

4. **IPv6 not supported** - Only IPv4 scanning implemented
   - Workaround: None (fundamental limitation, requires architectural changes)

5. **No proxy support** - Direct connections only
   - Future work: Add SOCKS5/HTTP proxy support

## Trust These Instructions

This file contains **validated information** (all build commands tested on Windows 11 with PowerShell 5.1, Go 1.23).

**When to search the codebase**:
- You need specific implementation details (function signatures, struct fields)
- Debugging unexpected behavior
- Information here is incomplete or contradictory
- Adding new features that interact with existing code

**When to trust this file**:
- Build/test/vet commands
- Project structure and file locations
- Package dependencies and design patterns
- Known issues and workarounds

For standard tasks (build, format, validate), follow commands exactly as documented. They are tested and known to work.

## Testing Conventions (CRITICAL)

**MANDATORY**: All test files MUST follow standard Go naming convention:
- ✅ **ONLY use `*_test.go`** - Standard Go test file naming
- ❌ **NEVER use `*_coverage_test.go`** - Non-standard, causes confusion
- ❌ **NEVER use `*_integration_test.go`** - Non-standard, consolidate into main test file
- ❌ **NEVER use `*_final_coverage_test.go`** - Non-standard, poor naming

**Rationale**: Go's convention is simple and clear. Multiple test file suffixes create:
- Confusion about which tests are "real" vs "coverage-focused"
- Duplicate test management overhead
- Inconsistent test execution
- Repository clutter

**Consolidation Strategy**:
1. **One `*_test.go` per source file** - e.g., `scanner.go` → `scanner_test.go`
2. **All tests in one file** - Unit, integration, coverage tests together
3. **Use t.Skip() for conditional tests** - Network tests, API tests with keys
4. **Group by functionality** - Not by test type (coverage/integration)

**Coverage Reporting**:
- Generate coverage with: `go test -coverprofile=coverage.txt ./...`
- View detailed report: `go tool cover -func=coverage.txt`
- **Use `*.coverprofile` pattern for testing** - e.g., `scanner.coverprofile`, `waf.coverprofile`
- **Primary coverage file**: `coverage.txt` at repository root
- **IMPORTANT**: Coverage files are gitignored - Copilot can read/write ignored files for testing
- Clean up with: `Remove-Item *.coverprofile, *_cov.txt, coverage.txt`

**Coverage File Naming Convention**:
- ✅ `coverage.txt` - Full project coverage report
- ✅ `*.coverprofile` - Package-specific coverage (e.g., `scanner.coverprofile`)
- ✅ `*_cov.txt` - Temporary package coverage files
- ❌ `cov`, `corecov`, `core_coverage` - Non-standard, avoid

**Working with Ignored Files**:
- Copilot has permission to edit files in `.gitignore` for testing purposes
- Coverage files are ignored but necessary for development
- Use absolute paths to avoid Go 1.25+ bug: `go test "-coverprofile=d:\full\path\coverage.txt"`

**Current Test Files** (32 total, all properly named):
```
cmd/origindive/main_test.go
internal/colors/colors_test.go
pkg/asn/asn_test.go
pkg/core/config_test.go
pkg/core/errors_test.go
pkg/core/globalconfig_test.go
pkg/core/result_test.go
pkg/ip/*.go (4 test files)
pkg/output/output_test.go
pkg/passive/* (11 test files for passive sources)
pkg/proxy/proxy_test.go
pkg/proxy/webshare_test.go
pkg/scanner/scanner_test.go
pkg/scanner/useragent_test.go
pkg/update/updater_test.go
pkg/waf/waf_test.go
```

**Test Organization Best Practices**:
- Table-driven tests for multiple scenarios
- Comprehensive field coverage (test all struct fields)
- Platform-aware tests (Windows vs Unix paths)
- Edge case testing (empty inputs, nil values, boundary conditions)
- Concurrent access tests for thread-safe code
- Mock external dependencies (network calls, file I/O)

## Changelog Management

**CRITICAL**: When adding features, fixing bugs, or making any user-facing changes:

1. **ALWAYS update CHANGELOG.md** in the `[Unreleased]` section
2. Use Keep a Changelog format with these categories:
   - `### Added` - New features
   - `### Changed` - Changes in existing functionality
   - `### Deprecated` - Soon-to-be removed features
   - `### Removed` - Removed features
   - `### Fixed` - Bug fixes
   - `### Security` - Vulnerability fixes

3. **Check latest version tag** before adding entries:
   ```powershell
   git tag --sort=-v:refname | Select-Object -First 5
   ```
   Latest: v3.1.0 (December 4, 2025)

4. **Entry format**:
   ```markdown
   ## [Unreleased]
   
   ### Added
   - Feature description with `backticks` for code/file names
   - Link to package: `pkg/feature/file.go`
   
   ### Fixed
   - Issue description (#issue-number if applicable)
   ```

5. **When ready to release**, move `[Unreleased]` content to a new version section:
   ```markdown
   ## [Unreleased]
   
   ## [3.2.0] - YYYY-MM-DD
   
   ### Added
   - Previous unreleased content here
   ```

**Example workflow**:
```markdown
## [Unreleased]

### Added
- Coverage-focused test files: `scanner_coverage_test.go`, `proxy_coverage_test.go`
- Test coverage improved from 49.2% to 58.3% overall
- Scanner package coverage: 20.1% → 56.1% (+36%)
- Proxy package coverage: 30.7% → 64.0% (+33%)

### Changed
- Updated `.gitignore` to exclude `*_coverage_test.go` and `*_integration_test.go`
- Added build artifacts patterns (`dist/`, `*.zip`, `*.tar.gz`)
```

This ensures release notes are always ready and nothing is forgotten.
