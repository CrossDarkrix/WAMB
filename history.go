package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
)

// FileState is the change-history record for one file.
type FileState struct {
	Size  int64 `json:"size"`
	Mtime int64 `json:"mtime"` // unix nano
}

type History struct {
	Files map[string]FileState `json:"files"`
}

func LoadHistory(path string) *History {
	h := &History{Files: map[string]FileState{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return h
	}
	_ = json.Unmarshal(data, h)
	if h.Files == nil {
		h.Files = map[string]FileState{}
	}
	return h
}

func (h *History) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// collectCurrent walks targets and stats every non-excluded regular file.
func collectCurrent(cfg *Config, targets []string, protected []string) map[string]FileState {
	cur := map[string]FileState{}
	for _, root := range targets {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if p != root && cfg.IsExcludedFile(p, protected) && !isProtectedPath(p, protected) {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			if cfg.IsExcludedFile(p, protected) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			cur[p] = FileState{Size: info.Size(), Mtime: info.ModTime().UnixNano()}
			return nil
		})
	}
	return cur
}

// ChangedFiles returns files that are new or whose size/mtime changed
// since the recorded history.
func ChangedFiles(prev *History, cur map[string]FileState) []string {
	var out []string
	for p, st := range cur {
		old, ok := prev.Files[p]
		if !ok || old.Size != st.Size || old.Mtime != st.Mtime {
			out = append(out, p)
		}
	}
	return out
}
