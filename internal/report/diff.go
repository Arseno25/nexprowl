package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Arseno25/nexprowl/internal/scanner"
)

type Diff struct {
	Old     string              `json:"old"`
	New     string              `json:"new"`
	Added   map[string][]string `json:"added"`
	Removed map[string][]string `json:"removed"`
	Changed bool                `json:"changed"`
}

func ComparePaths(oldPath, newPath string) (*Diff, error) {
	oldResults, err := loadResults(oldPath)
	if err != nil {
		return nil, fmt.Errorf("old results: %w", err)
	}
	newResults, err := loadResults(newPath)
	if err != nil {
		return nil, fmt.Errorf("new results: %w", err)
	}
	diff := &Diff{
		Old: oldPath, New: newPath,
		Added: map[string][]string{}, Removed: map[string][]string{},
	}
	for _, mode := range []string{"subdomains", "urls", "hostports", "ips", "endpoints", "web_state", "tls_state"} {
		oldSet, newSet := toSet(diffValues(oldResults, mode)), toSet(diffValues(newResults, mode))
		diff.Added[mode] = setDifference(newSet, oldSet)
		diff.Removed[mode] = setDifference(oldSet, newSet)
		if len(diff.Added[mode])+len(diff.Removed[mode]) > 0 {
			diff.Changed = true
		}
	}
	oldTakeovers, newTakeovers := takeoverSet(oldResults), takeoverSet(newResults)
	diff.Added["takeovers"] = setDifference(newTakeovers, oldTakeovers)
	diff.Removed["takeovers"] = setDifference(oldTakeovers, newTakeovers)
	if len(diff.Added["takeovers"])+len(diff.Removed["takeovers"]) > 0 {
		diff.Changed = true
	}
	return diff, nil
}

func (d *Diff) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "NexProwl diff\nold: %s\nnew: %s\n", d.Old, d.New)
	for _, mode := range []string{"subdomains", "urls", "hostports", "ips", "endpoints", "web_state", "tls_state", "takeovers"} {
		if len(d.Added[mode]) == 0 && len(d.Removed[mode]) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s: +%d -%d\n", mode, len(d.Added[mode]), len(d.Removed[mode]))
		for _, value := range d.Added[mode] {
			fmt.Fprintf(&b, "+ %s\n", value)
		}
		for _, value := range d.Removed[mode] {
			fmt.Fprintf(&b, "- %s\n", value)
		}
	}
	if !d.Changed {
		b.WriteString("\nno changes\n")
	}
	return b.String()
}

func diffValues(results []*scanner.Result, mode string) []string {
	if mode != "web_state" && mode != "tls_state" {
		return collect(results, mode)
	}
	var values []string
	for _, result := range results {
		switch mode {
		case "web_state":
			for _, web := range result.Web {
				values = append(values, fmt.Sprintf("%s | %d | %s | %s | %s",
					web.URL, web.Status, web.Title, web.BodyHash, strings.Join(web.Technologies, ",")))
			}
		case "tls_state":
			for _, tls := range result.TLSHosts {
				values = append(values, fmt.Sprintf("%s:%d | %s | %s | mismatch=%t",
					tls.Host, tls.Port, tls.Version, tls.ValidTo, tls.Mismatch))
			}
		}
	}
	sort.Strings(values)
	return values
}

func WriteDiff(path string, diff *Diff) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(diff, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func loadResults(path string) ([]*scanner.Result, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if info.IsDir() {
		files, err = filepath.Glob(filepath.Join(path, "*.json"))
		if err != nil {
			return nil, err
		}
	} else {
		files = []string{path}
	}
	var results []*scanner.Result
	for _, file := range files {
		if filepath.Base(file) == "manifest.json" || filepath.Base(file) == "diff.json" {
			continue
		}
		body, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var many []*scanner.Result
		if err := json.Unmarshal(body, &many); err == nil {
			results = append(results, many...)
			continue
		}
		var one scanner.Result
		if err := json.Unmarshal(body, &one); err == nil && one.Target != "" {
			results = append(results, &one)
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no JSON scan results found in %s", path)
	}
	return results, nil
}

func toSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func setDifference(a, b map[string]bool) []string {
	var out []string
	for value := range a {
		if !b[value] {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func takeoverSet(results []*scanner.Result) map[string]bool {
	set := map[string]bool{}
	for _, result := range results {
		for _, hit := range result.Takeovers {
			set[hit.Host+" → "+hit.Service] = true
		}
	}
	return set
}
