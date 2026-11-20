package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type QuarantineMeta struct {
	ID              string    `json:"id"`
	OriginalPath    string    `json:"original_path"`
	QuarantinedPath string    `json:"quarantined_path"`
	Signature       string    `json:"signature"`
	SHA256          string    `json:"sha256"`
	Size            int64     `json:"size"`
	ScanID          string    `json:"scan_id"`
	QuarantinedAt   time.Time `json:"quarantined_at"`
}

func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func moveFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// Cross-volume fallback: copy, verify size, then remove the source.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, st.Mode())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}

// QuarantineFile moves one detected file into the quarantine folder and
// records its metadata. Returns the quarantine entry id.
func QuarantineFile(cfg *Config, d Detection, scanID string) (string, error) {
	sum, size, err := fileSHA256(d.Path)
	if err != nil {
		return "", err
	}
	id := fmt.Sprintf("%s-%s", scanID, sum[:8])
	dst := filepath.Join(cfg.QuarantineDir, id, filepath.Base(d.Path))
	if err := moveFile(d.Path, dst); err != nil {
		return "", err
	}
	meta := QuarantineMeta{
		ID:              id,
		OriginalPath:    d.Path,
		QuarantinedPath: dst,
		Signature:       d.Signature,
		SHA256:          sum,
		Size:            size,
		ScanID:          scanID,
		QuarantinedAt:   time.Now(),
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(cfg.QuarantineDir, id, "meta.json"), data, 0o644); err != nil {
		return "", err
	}
	return id, nil
}

func ListQuarantine(cfg *Config) ([]QuarantineMeta, error) {
	ents, err := os.ReadDir(cfg.QuarantineDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []QuarantineMeta
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(cfg.QuarantineDir, e.Name(), "meta.json"))
		if err != nil {
			continue
		}
		var m QuarantineMeta
		if json.Unmarshal(data, &m) == nil {
			out = append(out, m)
		}
	}
	return out, nil
}

// RestoreQuarantine moves a quarantined file back to its original path.
func RestoreQuarantine(cfg *Config, id string) error {
	data, err := os.ReadFile(filepath.Join(cfg.QuarantineDir, id, "meta.json"))
	if err != nil {
		return err
	}
	var m QuarantineMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if _, err := os.Stat(m.OriginalPath); err == nil {
		return fmt.Errorf("destination already exists: %s", m.OriginalPath)
	}
	if err := moveFile(m.QuarantinedPath, m.OriginalPath); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(cfg.QuarantineDir, id))
}
