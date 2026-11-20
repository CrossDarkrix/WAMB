package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Config is the single WAMB configuration file (JSON).
type Config struct {
	ClamScanPath  string `json:"clamscan_path"`
	FreshClamPath string `json:"freshclam_path"`
	FreshClamConf string `json:"freshclam_conf,omitempty"`
	DatabaseDir   string `json:"database_dir,omitempty"`

	BaseDir       string `json:"base_dir"`       // state, reports, logs live here
	QuarantineDir string `json:"quarantine_dir"` // detected files are moved here on request
	MirrorDir     string `json:"mirror_dir"`     // latest reports mirrored here for Muse ("" disables)

	Targets      []string `json:"targets"`       // folders scanned by default
	ExcludeFiles []string `json:"exclude_files"` // exact paths never scanned/reported
	ExcludeDirs  []string `json:"exclude_dirs"`  // folders never scanned (prefix match)
	ExcludeRegex []string `json:"exclude_regex"` // extra clamscan --exclude patterns
	Level        int      `json:"level"`         // detection sensitivity 1..3

	NotifyOnDetect bool   `json:"notify_on_detect"`
	DiscordWebhook string `json:"discord_webhook"`

	WatchDebounceSec int  `json:"watch_debounce_sec"`
	WatchQuarantine  bool `json:"watch_quarantine"` // auto-quarantine detections found by watch

	ScheduleScan   string `json:"schedule_scan"`   // "03:00" (used by the service phase)
	ScheduleUpdate string `json:"schedule_update"` // "02:00"
}

func defaultBaseDir() string {
	if v := os.Getenv("WAMB_HOME"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		if lad := os.Getenv("LOCALAPPDATA"); lad != "" {
			return filepath.Join(lad, "WAMB")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".wamb")
}

func DefaultConfig() *Config {
	base := defaultBaseDir()
	home, _ := os.UserHomeDir()
	cfg := &Config{
		ClamScanPath:  `C:\Program Files\ClamAV\clamscan.exe`,
		FreshClamPath: `C:\Program Files\ClamAV\freshclam.exe`,
		BaseDir:       base,
		QuarantineDir: filepath.Join(base, "quarantine"),
		Targets: []string{
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "Desktop"),
		},
		Level:            2,
		NotifyOnDetect:   true,
		WatchDebounceSec: 3,
		ScheduleScan:     "03:00",
		ScheduleUpdate:   "02:00",
	}
	if runtime.GOOS == "windows" {
		cfg.MirrorDir = `C:\Muse\wamb`
	}
	return cfg
}

func configPath(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("WAMB_CONFIG"); v != "" {
		return v
	}
	return filepath.Join(defaultBaseDir(), "config.json")
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // defaults until `wamb init` writes one
		}
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if cfg.Level < 1 || cfg.Level > 3 {
		return nil, fmt.Errorf("config: level must be 1..3, got %d", cfg.Level)
	}
	return cfg, nil
}

func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (c *Config) reportsDir() string { return filepath.Join(c.BaseDir, "reports") }
func (c *Config) stateFile() string  { return filepath.Join(c.BaseDir, "history.json") }
func (c *Config) lockFile() string   { return filepath.Join(c.BaseDir, "wamb.lock") }
func (c *Config) ensureDirs() error {
	for _, d := range []string{c.BaseDir, c.reportsDir(), c.QuarantineDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// ProtectedTargets returns browser cookie / login stores that must always be
// monitored. Per the owner's requirement, excludes never apply to these.
func ProtectedTargets() []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	return protectedFor(os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA"))
}

// protectedFor builds the browser profile roots for one user's AppData pair.
func protectedFor(lad, rad string) []string {
	var out []string
	add := func(p string) {
		if p != "" {
			out = append(out, p)
		}
	}
	// Chromium-family profile roots (Cookies / Login Data live under these).
	for _, root := range []string{
		filepath.Join(lad, "Google", "Chrome", "User Data"),
		filepath.Join(lad, "Microsoft", "Edge", "User Data"),
		filepath.Join(lad, "BraveSoftware", "Brave-Browser", "User Data"),
		filepath.Join(lad, "Vivaldi", "User Data"),
		filepath.Join(lad, "Chromium", "User Data"),
		filepath.Join(rad, "Opera Software", "Opera Stable"),
	} {
		add(root)
	}
	// Firefox profile roots.
	ff := filepath.Join(rad, "Mozilla", "Firefox", "Profiles")
	if ents, err := os.ReadDir(ff); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				add(filepath.Join(ff, e.Name()))
			}
		}
	}
	return out
}

// userProfiles lists real user profile directories (C:\Users\<name>),
// skipping the built-in template/system entries.
func userProfiles() []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	ents, err := os.ReadDir(`C:\Users`)
	if err != nil {
		return nil
	}
	skip := map[string]bool{
		"default": true, "default user": true, "public": true, "all users": true,
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && !skip[strings.ToLower(e.Name())] {
			out = append(out, filepath.Join(`C:\Users`, e.Name()))
		}
	}
	return out
}

// effectiveProtected returns the protected browser roots for this process:
// the current user's, plus every user profile's when running as SYSTEM
// (the service has no user profile of its own worth monitoring).
func effectiveProtected() []string {
	out := ProtectedTargets()
	if isSystemUser() {
		seen := map[string]bool{}
		for _, p := range out {
			seen[normPath(p)] = true
		}
		for _, prof := range userProfiles() {
			lad := filepath.Join(prof, "AppData", "Local")
			rad := filepath.Join(prof, "AppData", "Roaming")
			for _, r := range protectedFor(lad, rad) {
				if !seen[normPath(r)] {
					seen[normPath(r)] = true
					out = append(out, r)
				}
			}
		}
	}
	return out
}

// effectiveTargets expands the configured targets for a SYSTEM process:
// every user profile's Downloads/Desktop folders are added.
func (c *Config) effectiveTargets() []string {
	out := append([]string{}, c.Targets...)
	if isSystemUser() {
		seen := map[string]bool{}
		for _, t := range out {
			seen[normPath(t)] = true
		}
		for _, prof := range userProfiles() {
			for _, sub := range []string{"Downloads", "Desktop"} {
				p := filepath.Join(prof, sub)
				if !seen[normPath(p)] {
					if st, err := os.Stat(p); err == nil && st.IsDir() {
						seen[normPath(p)] = true
						out = append(out, p)
					}
				}
			}
		}
	}
	return out
}

// isProtectedPath reports whether p sits under a protected browser target.
func isProtectedPath(p string, protected []string) bool {
	np := normPath(p)
	for _, root := range protected {
		nr := normPath(root)
		if np == nr || strings.HasPrefix(np, nr+"/") {
			return true
		}
	}
	return false
}

// normPath canonicalizes a path for comparisons: forward slashes, cleaned,
// lowercased on Windows (case-insensitive filesystem).
func normPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean(p)
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

// regexForPath renders a filesystem path as a regex fragment in which every
// separator matches either slash direction (clamscan sees Windows paths).
func regexForPath(p string) string {
	np := strings.ReplaceAll(filepath.Clean(p), "\\", "/")
	segs := strings.Split(np, "/")
	for i, s := range segs {
		segs[i] = regexp.QuoteMeta(s)
	}
	return strings.Join(segs, `[\\/]`)
}

// EffectiveExcludes resolves the config excludes into clamscan regex patterns,
// dropping any pattern that would hide a protected browser target.
func (c *Config) EffectiveExcludes(protected []string) (patterns []string, warnings []string) {
	seen := map[string]bool{}
	add := func(pat string) {
		if pat == "" || seen[pat] {
			return
		}
		seen[pat] = true
		patterns = append(patterns, pat)
	}
	for _, f := range c.ExcludeFiles {
		if isProtectedPath(f, protected) {
			warnings = append(warnings, "exclude ignored (protected browser target): "+f)
			continue
		}
		add("^" + regexForPath(f) + "$")
	}
	for _, d := range c.ExcludeDirs {
		if isProtectedPath(d, protected) {
			warnings = append(warnings, "exclude ignored (protected browser target): "+d)
			continue
		}
		add("^" + regexForPath(d) + `([\\/].*)?$`)
	}
	for _, rx := range c.ExcludeRegex {
		re, err := regexp.Compile(rx)
		if err != nil {
			warnings = append(warnings, "invalid exclude_regex skipped: "+rx)
			continue
		}
		blocked := false
		for _, p := range protected {
			if re.MatchString(normPath(p)) {
				blocked = true
				break
			}
		}
		if blocked {
			warnings = append(warnings, "exclude_regex ignored (matches a protected browser target): "+rx)
			continue
		}
		add(rx)
	}
	return patterns, warnings
}

// IsExcludedFile is the Go-side filter used by watch/history, mirroring the
// clamscan-side patterns: exact files, directory prefixes, then regexes.
func (c *Config) IsExcludedFile(p string, protected []string) bool {
	if isProtectedPath(p, protected) {
		return false
	}
	np := normPath(p)
	for _, f := range c.ExcludeFiles {
		if np == normPath(f) {
			return true
		}
	}
	for _, d := range c.ExcludeDirs {
		nd := normPath(d)
		if np == nd || strings.HasPrefix(np, nd+"/") {
			return true
		}
	}
	for _, rx := range c.ExcludeRegex {
		if re, err := regexp.Compile(rx); err == nil && re.MatchString(np) {
			return true
		}
	}
	return false
}
