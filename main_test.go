package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Arseno25/nexprowl/internal/report"
	"github.com/Arseno25/nexprowl/internal/scanner"
)

// buildBinary compiles the CLI into a temp dir with the given extra build
// flags and returns its path.
func buildBinary(t *testing.T, extra ...string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "nexprowl")
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		binary += ".exe"
		goBinary += ".exe"
	}
	args := append([]string{"build", "-trimpath"}, extra...)
	args = append(args, "-o", binary, ".")
	if output, err := exec.Command(goBinary, args...).CombinedOutput(); err != nil {
		t.Fatalf("build %v failed: %v\n%s", args, err, output)
	}
	return binary
}

// TestVersionLinkerFlags pins the exact -X paths used by .goreleaser.yaml, so
// a package move that silently breaks release version stamping fails here.
func TestVersionLinkerFlags(t *testing.T) {
	const pkg = "github.com/Arseno25/nexprowl/internal/scanner"
	binary := buildBinary(t, "-ldflags",
		"-X "+pkg+".Version=9.9.9 -X "+pkg+".Commit=deadbeef -X "+pkg+".Date=2026-01-02T03:04:05Z")

	output, err := exec.Command(binary, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("version: %v\n%s", err, output)
	}
	for _, want := range []string{"NexProwl 9.9.9", "deadbeef", "2026-01-02T03:04:05Z"} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("version output %q missing %q", output, want)
		}
	}
}

func TestCLIHelpVersionAndValidation(t *testing.T) {
	binary := buildBinary(t)

	// Both spellings must report the same build metadata, and the linker-flag
	// variables must survive a plain build with their documented defaults.
	for _, args := range [][]string{{"-version"}, {"--version"}, {"version"}} {
		output, err := exec.Command(binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, output)
		}
		for _, want := range []string{
			"NexProwl " + scanner.Version, "commit:", "built:", "go:", "os/arch:",
			runtime.GOOS + "/" + runtime.GOARCH,
		} {
			if !strings.Contains(string(output), want) {
				t.Fatalf("%v output %q missing %q", args, output, want)
			}
		}
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
