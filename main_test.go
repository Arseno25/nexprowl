package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"nexprowl/internal/report"
	"nexprowl/internal/scanner"
)

func TestCLIHelpVersionAndValidation(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "nexprowl")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		goBinary += ".exe"
	}
	build := exec.Command(goBinary, "build", "-trimpath", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("manual build failed: %v\n%s", err, output)
	}

	version := exec.Command(binary, "-version")
	if output, err := version.CombinedOutput(); err != nil ||
		!strings.Contains(string(output), "NexProwl v"+scanner.Version) {
		t.Fatalf("version output = %q, %v", output, err)
	}
	help := exec.Command(binary, "-no-color", "-h")
	if output, err := help.CombinedOutput(); err != nil ||
		!strings.Contains(string(output), "nexprowl [flags]") ||
		!strings.Contains(string(output), "-screenshot") {
		t.Fatalf("help output = %q, %v", output, err)
	}
	invalid := exec.Command(binary, "-m", "unknown", "example.com")
	if output, err := invalid.CombinedOutput(); err == nil ||
		!strings.Contains(string(output), `unknown module "unknown"`) {
		t.Fatalf("invalid config output = %q, %v", output, err)
	}
}

func TestRunDiff(t *testing.T) {
	root := t.TempDir()
	oldPath, newPath := filepath.Join(root, "old.json"), filepath.Join(root, "new.json")
	if _, err := report.Save(oldPath, "", []*scanner.Result{{Target: "example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := report.Save(newPath, "", []*scanner.Result{{
		Target: "example.com", Endpoints: []scanner.Endpoint{{URL: "https://example.com/api"}},
	}}); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(root, "diff.json")

	oldStdout := os.Stdout
	stdout, err := os.Create(filepath.Join(root, "stdout.txt"))
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = stdout
	changed, runErr := runDiff([]string{"-o", outputPath, oldPath, newPath})
	os.Stdout = oldStdout
	_ = stdout.Close()
	if runErr != nil || !changed {
		t.Fatalf("runDiff changed=%v err=%v", changed, runErr)
	}
	if body, err := os.ReadFile(outputPath); err != nil ||
		!strings.Contains(string(body), `"changed": true`) {
		t.Fatalf("diff file = %q, %v", body, err)
	}
	if _, err := runDiff([]string{oldPath}); err == nil {
		t.Fatal("runDiff accepted one path")
	}
}
