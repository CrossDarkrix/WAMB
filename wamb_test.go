package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseClamscanOutput(t *testing.T) {
	out := "C:\\Users\\x\\Downloads\\evil.exe: Win.Trojan.Agent-123 FOUND\n" +
		"C:\\Users\\x\\Downloads\\ok.txt: OK\n" +
		"----------- SCAN SUMMARY -----------\n" +
		"Scanned files: 42\n" +
		"Infected files: 1\n"
	rep := &Report{}
	parseClamscanOutput(rep, out)
	if rep.ScannedFiles != 42 {
		t.Fatalf("scanned = %d, want 42", rep.ScannedFiles)
	}
	if len(rep.Detections) != 1 {
		t.Fatalf("detections = %d, want 1", len(rep.Detections))
	}
	d := rep.Detections[0]
	if d.Path != `C:\Users\x\Downloads\evil.exe` || d.Signature != "Win.Trojan.Agent-123" {
		t.Fatalf("bad detection: %+v", d)
	}
	if rep.Infected != 1 {
		t.Fatalf("infected = %d, want 1", rep.Infected)
	}
}

func TestLevelArgs(t *testing.T) {
	if got := levelArgs(1); len(got) != 0 {
		t.Fatalf("level1 should add no flags, got %v", got)
	}
	high := strings.Join(levelArgs(3), " ")
	if !strings.Contains(high, "--detect-pua=yes") {
		t.Fatalf("level3 should enable PUA: %s", high)
	}
}

func TestExcludeProtection(t *testing.T) {
	protected := []string{`C:\Users\x\AppData\Local\Google\Chrome\User Data`}
	cfg := &Config{
		ExcludeDirs: []string{`C:\Users\x\AppData\Local\Google\Chrome\User Data`, `C:\msys64`},
	}
	patterns, warnings := cfg.EffectiveExcludes(protected)
	if len(warnings) != 1 {
		t.Fatalf("want 1 protection warning, got %v", warnings)
	}
	if len(patterns) != 1 {
		t.Fatalf("want 1 surviving pattern, got %v", patterns)
	}
	cookie := `C:\Users\x\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`
	if !isProtectedPath(cookie, protected) {
		t.Fatal("cookie path should be protected")
	}
	if cfg.IsExcludedFile(cookie, protected) {
		t.Fatal("protected cookie file must never be excluded")
	}
}

func TestChangedFiles(t *testing.T) {
	prev := &History{Files: map[string]FileState{
		"a.txt": {Size: 10, Mtime: 100},
		"b.txt": {Size: 20, Mtime: 200},
	}}
	cur := map[string]FileState{
		"a.txt": {Size: 10, Mtime: 100}, // unchanged
		"b.txt": {Size: 21, Mtime: 200}, // size changed
		"c.txt": {Size: 1, Mtime: 1},    // new
	}
	got := ChangedFiles(prev, cur)
	if len(got) != 2 {
		t.Fatalf("changed = %v, want 2 entries", got)
	}
}

func TestDueToday(t *testing.T) {
	loc := time.FixedZone("JST", 9*3600)
	now := time.Date(2026, 11, 21, 3, 30, 0, 0, loc)
	if !dueToday("", now, "03:00") {
		t.Fatal("03:00 job should be due at 03:30 when never run")
	}
	if dueToday("2026-11-21", now, "03:00") {
		t.Fatal("job already ran today must not be due")
	}
	if dueToday("", now, "04:00") {
		t.Fatal("04:00 job must not be due at 03:30")
	}
	if !dueToday("2026-11-20", now, "03:00") {
		t.Fatal("job that ran yesterday should be due")
	}
	if dueToday("", now, "not-a-time") {
		t.Fatal("invalid schedule must never be due")
	}
}

func TestQuarantineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{QuarantineDir: filepath.Join(dir, "q"), BaseDir: dir}
	victim := filepath.Join(dir, "evil.bin")
	if err := os.WriteFile(victim, []byte("not really malware"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := QuarantineFile(cfg, Detection{Path: victim, Signature: "Test.Sig"}, "scan1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatal("original should be gone after quarantine")
	}
	items, err := ListQuarantine(cfg)
	if err != nil || len(items) != 1 {
		t.Fatalf("list = %v, %v", items, err)
	}
	if err := RestoreQuarantine(cfg, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatal("file should be restored:", err)
	}
}
