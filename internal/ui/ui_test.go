package ui

import (
	"testing"

	"dscan/internal/scanner"
)

func TestHTTPStatusLevel(t *testing.T) {
	tests := map[int]scanner.Level{
		0:   scanner.LevelInfo,
		204: scanner.LevelSuccess,
		302: scanner.LevelInfo,
		404: scanner.LevelWarn,
		503: scanner.LevelError,
	}
	for code, want := range tests {
		if got := httpStatusLevel(code); got != want {
			t.Errorf("status %d: got %s, want %s", code, got, want)
		}
	}
}
