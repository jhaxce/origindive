// Package update provides self-update functionality for origindive
package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jhaxce/origindive/v3/internal/version"
)

const (
	// GitHubReleasesAPI is the primary GitHub API endpoint for releases
	GitHubReleasesAPI = "https://api.github.com/repos/jhaxce/origindive/releases/latest"

	// GitHubReleasesAPIFallback is the fallback endpoint via web interface
	GitHubReleasesWebURL = "https://github.com/jhaxce/origindive/releases/latest"

	// UpdateCheckInterval is how often to check for updates
	UpdateCheckInterval = 24 * time.Hour
)

// Release represents a GitHub release
type Release struct {
	TagName    string  `json:"tag_name"`
	Name       string  `json:"name"`
	Body       string  `json:"body"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	CreatedAt  string  `json:"created_at"`
	Assets     []Asset `json:"assets"`
}

// Asset represents a release asset
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// UpdateInfo contains information about an available update
type UpdateInfo struct {
	CurrentVersion string
	LatestVersion  string
	ReleaseURL     string
	ReleaseNotes   string
	DownloadURL    string
	AssetName      string
}

// CheckForUpdate checks if a newer version is available
func CheckForUpdate() (*UpdateInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", GitHubReleasesAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch release info from GitHub API: %w\nFallback: Check manually at %s", err, GitHubReleasesWebURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("GitHub API rate limit exceeded. Please try again later or check manually at %s", GitHubReleasesWebURL)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d. Check manually at %s", resp.StatusCode, GitHubReleasesWebURL)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse release info: %w", err)
	}

	// Skip drafts and prereleases
	if release.Draft || release.Prerelease {
		return nil, nil
	}

	// Compare versions
	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(version.Version, "v")

	if latestVersion == currentVersion {
		return nil, nil // Already up to date
	}

	// Find the appropriate asset for this platform. Support both
	// underscore and dash separators for backward compatibility with older releases.
	assetName := fmt.Sprintf("origindive_v%s_%s_%s", latestVersion, runtime.GOOS, runtime.GOARCH)
	var expectedExt string
	if runtime.GOOS == "windows" {
		expectedExt = ".zip"
	} else {
		expectedExt = ".tar.gz"
	}
	assetName = assetName + expectedExt

	// Also accept a dash-separated legacy name: origindive-<version>-<os>-<arch>.<ext>
	legacyAssetName := strings.ReplaceAll(assetName, "_", "-")

	var downloadURL string
	var matchedAsset string
	for _, asset := range release.Assets {
		if asset.Name == assetName || asset.Name == legacyAssetName {
			downloadURL = asset.BrowserDownloadURL
			matchedAsset = asset.Name
			break
		}
	}

	if downloadURL == "" {
		return nil, fmt.Errorf("no compatible binary found for %s/%s (checked %s and %s)", runtime.GOOS, runtime.GOARCH, assetName, legacyAssetName)
	}

	return &UpdateInfo{
		CurrentVersion: currentVersion,
		LatestVersion:  latestVersion,
		ReleaseURL:     fmt.Sprintf("https://github.com/jhaxce/origindive/releases/tag/%s", release.TagName),
		ReleaseNotes:   release.Body,
		DownloadURL:    downloadURL,
		AssetName:      matchedAsset,
	}, nil
}

// DownloadUpdate downloads the update to a temporary file
func DownloadUpdate(info *UpdateInfo) (string, error) {
	client := &http.Client{Timeout: 5 * time.Minute}

	resp, err := client.Get(info.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Determine extension from asset name (prefer) or download URL
	ext := ""
	if info != nil && info.AssetName != "" {
		if strings.HasSuffix(info.AssetName, ".tar.gz") {
			ext = ".tar.gz"
		} else {
			ext = filepath.Ext(info.AssetName)
		}
	}
	if ext == "" {
		// Fallback to extension from URL path
		if u, err := http.NewRequest("GET", info.DownloadURL, nil); err == nil {
			base := filepath.Base(u.URL.Path)
			if strings.HasSuffix(base, ".tar.gz") {
				ext = ".tar.gz"
			} else {
				ext = filepath.Ext(base)
			}
		}
	}

	// Create temporary file with proper extension so ExtractBinary can detect format
	pattern := "origindive-update-*"
	if ext != "" {
		pattern = pattern + ext
	}
	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	// Download to temp file
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to save update: %w", err)
	}

	return tmpFile.Name(), nil
}

// ExtractBinary extracts the binary from the downloaded archive
func ExtractBinary(archivePath string) (string, error) {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractZip(archivePath)
	} else if strings.HasSuffix(archivePath, ".tar.gz") {
		return extractTarGz(archivePath)
	}
	return "", fmt.Errorf("unsupported archive format")
}

// extractZip extracts a Windows ZIP archive
func extractZip(archivePath string) (string, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("failed to open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if strings.HasSuffix(f.Name, "origindive.exe") || f.Name == "origindive" {
			rc, err := f.Open()
			if err != nil {
				return "", fmt.Errorf("failed to open file in zip: %w", err)
			}
			defer rc.Close()

			tmpFile, err := os.CreateTemp("", "origindive-new-*.exe")
			if err != nil {
				return "", fmt.Errorf("failed to create temp file: %w", err)
			}
			defer tmpFile.Close()

			if _, err := io.Copy(tmpFile, rc); err != nil {
				os.Remove(tmpFile.Name())
				return "", fmt.Errorf("failed to extract binary: %w", err)
			}

			if err := tmpFile.Chmod(0755); err != nil {
				os.Remove(tmpFile.Name())
				return "", fmt.Errorf("failed to set permissions: %w", err)
			}

			return tmpFile.Name(), nil
		}
	}

	return "", fmt.Errorf("binary not found in archive")
}

// extractTarGz extracts a Linux/macOS tar.gz archive
func extractTarGz(archivePath string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("failed to open archive: %w", err)
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read tar: %w", err)
		}

		if header.Name == "origindive" || strings.HasSuffix(header.Name, "/origindive") {
			tmpFile, err := os.CreateTemp("", "origindive-new-*")
			if err != nil {
				return "", fmt.Errorf("failed to create temp file: %w", err)
			}
			defer tmpFile.Close()

			if _, err := io.Copy(tmpFile, tr); err != nil {
				os.Remove(tmpFile.Name())
				return "", fmt.Errorf("failed to extract binary: %w", err)
			}

			if err := tmpFile.Chmod(0755); err != nil {
				os.Remove(tmpFile.Name())
				return "", fmt.Errorf("failed to set permissions: %w", err)
			}

			return tmpFile.Name(), nil
		}
	}

	return "", fmt.Errorf("binary not found in archive")
}

// ReplaceCurrentBinary replaces the running binary with the new one
func ReplaceCurrentBinary(newBinaryPath string) error {
	// Get current executable path
	currentPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	// Resolve symlinks
	currentPath, err = filepath.EvalSymlinks(currentPath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Create backup
	backupPath := currentPath + ".old"
	if err := os.Rename(currentPath, backupPath); err != nil {
		return fmt.Errorf("failed to backup current binary: %w", err)
	}

	// Copy new binary to current location
	if err := copyFile(newBinaryPath, currentPath); err != nil {
		// Restore backup on failure
		os.Rename(backupPath, currentPath)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	// Set executable permissions
	if err := os.Chmod(currentPath, 0755); err != nil {
		os.Rename(backupPath, currentPath)
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Clean up
	os.Remove(backupPath)
	os.Remove(newBinaryPath)

	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return dstFile.Sync()
}

// VerifyChecksum verifies the SHA256 checksum of a file
func VerifyChecksum(filepath string, expectedChecksum string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// Update performs a complete update process
func Update() error {
	fmt.Println("Checking for updates...")

	info, err := CheckForUpdate()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	if info == nil {
		fmt.Println("You are already running the latest version.")
		return nil
	}

	fmt.Printf("New version available: %s (current: %s)\n", info.LatestVersion, info.CurrentVersion)
	fmt.Printf("Release URL: %s\n", info.ReleaseURL)
	fmt.Println("\nDownloading update...")

	archivePath, err := DownloadUpdate(info)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer os.Remove(archivePath)

	fmt.Println("Extracting binary...")
	binaryPath, err := ExtractBinary(archivePath)
	if err != nil {
		return fmt.Errorf("failed to extract binary: %w", err)
	}

	fmt.Println("Installing update...")
	if err := ReplaceCurrentBinary(binaryPath); err != nil {
		return fmt.Errorf("failed to install update: %w", err)
	}

	fmt.Printf("\nSuccessfully updated to version %s!\n", info.LatestVersion)
	fmt.Println("Please restart origindive to use the new version.")

	return nil
}
