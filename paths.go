package main

import (
	"os"
	"path/filepath"
)

// Default file locations. An explicit flag always wins; otherwise the first
// existing file in the search list is used, so honeydet works both from a
// source checkout and when installed system-wide (for example as a package).

// userConfigDir returns $XDG_CONFIG_HOME/honeydet or ~/.config/honeydet.
func userConfigDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "honeydet")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "honeydet")
	}
	return ""
}

// userDataDir returns $XDG_DATA_HOME/honeydet or ~/.local/share/honeydet.
func userDataDir() string {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "honeydet")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share", "honeydet")
	}
	return ""
}

// executableDir returns the directory holding the running binary.
func executableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe)
}

func signatureSearchPaths() []string {
	return candidatePaths("signatures.yaml",
		".", userConfigDir(), executableDir(), "/usr/local/share/honeydet", "/usr/share/honeydet")
}

func configSearchPaths() []string {
	return candidatePaths("config.yaml", ".", userConfigDir(), "/etc/honeydet")
}

func candidatePaths(name string, dirs ...string) []string {
	var paths []string
	for _, dir := range dirs {
		if dir != "" {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	return paths
}

// firstExisting returns the first path that exists, or fallback if none does.
func firstExisting(paths []string, fallback string) string {
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return fallback
}

// defaultDatabasePath returns the scan database location, creating its directory.
// Falls back to ./scans.db when no home directory is available.
func defaultDatabasePath() string {
	dir := userDataDir()
	if dir == "" || os.MkdirAll(dir, 0o700) != nil {
		return "scans.db"
	}
	return filepath.Join(dir, "scans.db")
}
