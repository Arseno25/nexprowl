package scanner

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Module is a single scan capability.
type Module interface {
	Name() string
	Run(ctx context.Context, sc *ScanContext) error
}

// Engine runs modules against targets with bounded concurrency.
type Engine struct {
	opts    *Options
	modules []Module // ordered
	emit    Emitter
}

// NewEngine builds an engine. Module order = execution order.
func NewEngine(opts *Options, modules []Module, emit Emitter) *Engine {
	// filter by enabled modules, keep registry order
	active := make([]Module, 0, len(modules))
	for _, m := range modules {
		if opts.HasModule(m.Name()) {
			active = append(active, m)
		}
	}
	return &Engine{opts: opts, modules: active, emit: emit}
}

// Run scans all targets and returns results in input order.
func (e *Engine) Run(ctx context.Context, targets []string) []*Result {
	results := make([]*Result, len(targets))
	sem := make(chan struct{}, max(1, e.opts.Concurrency))
	var wg sync.WaitGroup

	for i, target := range targets {
		// Take the slot before spawning: otherwise a large -l list parks one
		// goroutine per target waiting on the semaphore.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			results[i] = &Result{Target: target, Error: "cancelled"}
			continue
		}

		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				results[i] = &Result{Target: target, Error: "cancelled"}
				return
			}
			results[i] = e.runTarget(ctx, target)

			if e.emit != nil {
				e.emit(Event{Type: EvTargetDone, Target: results[i].Target, Level: LevelSuccess})
			}
		}(i, target)
	}
	wg.Wait()
	return results
}

// runTarget executes modules sequentially for one target.
// (Modules parallelize internally; DNS must precede subdomains, etc.)
func (e *Engine) runTarget(ctx context.Context, target string) *Result {
	start := time.Now()
	sc := NewScanContext(target, e.opts, e.emit)

	for _, m := range e.modules {
		if ctx.Err() != nil {
			break
		}
		sc.Phase(m.Name())
		func() {
			defer func() {
				if r := recover(); r != nil {
					sc.SetError("module %s panicked: %v", m.Name(), r)
				}
			}()
			if err := m.Run(ctx, sc); err != nil {
				sc.SetError("module %s: %v", m.Name(), err)
			}
		}()
	}

	sc.Result.DurationMs = time.Since(start).Milliseconds()
	return sc.Result
}

// ─── Shared helpers ───────────────────────────────────────

// UniqueSorted dedupes and sorts a string slice.
func UniqueSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
