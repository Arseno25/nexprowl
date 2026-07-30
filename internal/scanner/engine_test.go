package scanner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type testModule struct {
	name string
	run  func(*ScanContext) error
}

func (m testModule) Name() string { return m.name }
func (m testModule) Run(_ context.Context, sc *ScanContext) error {
	if m.run == nil {
		return nil
	}
	return m.run(sc)
}

func TestEngineOrderFilteringAndErrors(t *testing.T) {
	var order []string
	modules := []Module{
		testModule{"one", func(*ScanContext) error { order = append(order, "one"); return errors.New("failed") }},
		testModule{"skip", func(*ScanContext) error { order = append(order, "skip"); return nil }},
		testModule{"panic", func(*ScanContext) error { panic("boom") }},
	}
	engine := NewEngine(&Options{
		Modules: map[string]bool{"one": true, "panic": true}, Concurrency: 1,
	}, modules, nil)
	results := engine.Run(context.Background(), []string{"a.example", "b.example"})
	if len(results) != 2 || results[0].Target != "a.example" || results[1].Target != "b.example" {
		t.Fatalf("results not in input order: %#v", results)
	}
	if strings.Contains(strings.Join(order, ","), "skip") {
		t.Fatalf("filtered module ran: %v", order)
	}
	for _, result := range results {
		if len(result.Errors) != 2 || !strings.Contains(strings.Join(result.Errors, " "), "boom") {
			t.Fatalf("errors not aggregated: %#v", result.Errors)
		}
	}
}

func TestRateLimiterCancellation(t *testing.T) {
	limiter := NewRateLimiter(1)
	limiter.Wait(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	limiter.Wait(ctx)
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("rate limiter ignored cancellation")
	}
}

func TestEngineEmitsNumberedPhases(t *testing.T) {
	var phases []Event
	engine := NewEngine(&Options{Concurrency: 1}, []Module{
		testModule{name: "one"},
		testModule{name: "two"},
	}, func(ev Event) {
		if ev.Type == EvPhase {
			phases = append(phases, ev)
		}
	})
	engine.Run(context.Background(), []string{"example.com"})

	if len(phases) != 2 || phases[0].Step != 1 || phases[1].Step != 2 || phases[1].Total != 2 {
		t.Fatalf("unexpected phase metadata: %#v", phases)
	}
}

func TestUniqueSorted(t *testing.T) {
	got := UniqueSorted([]string{"b", "a", "b", "c", "a"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UniqueSorted = %v, want %v", got, want)
	}
}
