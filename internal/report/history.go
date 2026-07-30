package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"dscan/internal/scanner"
)

type Manifest struct {
	Version    string   `json:"version"`
	Generated  string   `json:"generated"`
	Targets    []string `json:"targets"`
	Subdomains int      `json:"subdomains"`
	Ports      int      `json:"ports"`
	Live       int      `json:"live_web"`
	Endpoints  int      `json:"endpoints"`
	Takeovers  int      `json:"takeovers"`
	Errors     int      `json:"errors"`
}

func NewManifest(results []*scanner.Result) Manifest {
	manifest := Manifest{
		Version: scanner.Version, Generated: time.Now().Format(time.RFC3339),
	}
	for _, r := range results {
		manifest.Targets = append(manifest.Targets, r.Target)
		manifest.Subdomains += len(r.Subdomains)
		manifest.Ports += len(r.Ports)
		manifest.Live += len(r.Web)
		manifest.Endpoints += len(r.Endpoints)
		manifest.Takeovers += len(r.Takeovers)
		manifest.Errors += len(r.Errors)
	}
	return manifest
}

// ResolveOutputPath gives every directory-mode scan an immutable run folder.
func ResolveOutputPath(path string, now time.Time) string {
	if path == "" || filepath.Ext(path) != "" {
		return path
	}
	name := fmt.Sprintf("%s-%03d", now.Format("20060102-150405"), now.Nanosecond()/int(time.Millisecond))
	return filepath.Join(path, name)
}

func ArtifactDir(path string) string {
	if filepath.Ext(path) != "" {
		return filepath.Join(filepath.Dir(path), "screenshots")
	}
	return filepath.Join(path, "screenshots")
}

func writeManifest(path string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}
