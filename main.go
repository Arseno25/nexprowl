// NexProwl — all-in-one domain reconnaissance tool.
//
// Combines techniques from subfinder, gobuster, rustscan, httpx,
// wappalyzer, wafw00f, dnsrecon and subjack into one fast binary.
//
// Author: shadow0x0
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nexprowl/internal/config"
	"nexprowl/internal/modules"
	"nexprowl/internal/report"
	"nexprowl/internal/scanner"
	"nexprowl/internal/ui"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "diff" {
		changed, err := runDiff(os.Args[2:])
		if err != nil {
			fatal("diff: %v", err)
		}
		if changed {
			os.Exit(3)
		}
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fatal("%v", err)
	}
	if cfg.NoColor {
		ui.DisableColors()
	}
	if cfg.ShowHelp {
		ui.PrintHelp()
		return
	}
	if cfg.ShowVer {
		fmt.Printf("NexProwl v%s by shadow0x0\n", scanner.Version)
		return
	}
	cfg.Output = report.ResolveOutputPath(cfg.Output, time.Now())

	// ── UI setup ──
	var renderer *ui.UI
	var emit scanner.Emitter
	if !cfg.Silent {
		ui.Banner()
		ui.Boot()
		ui.ConfigLine(len(cfg.Targets), cfg.Modules, cfg.Opts.Workers,
			cfg.Opts.Concurrency, cfg.TimeoutS, cfg.Opts.Rate, len(cfg.Opts.Resolvers), cfg.Opts.Stealth)
		renderer = ui.NewUI(len(cfg.Targets))
		go renderer.Run()
		emit = renderer.Emitter()
	}

	// ── graceful cancel ──
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// ── run engine ──
	engine := scanner.NewEngine(cfg.Opts, modules.All(), emit)
	results := engine.Run(ctx, cfg.Targets)

	if renderer != nil {
		renderer.Close()
	}
	if cfg.Opts.Screenshot {
		if err := modules.CaptureScreenshots(ctx, report.ArtifactDir(cfg.Output), results, cfg.Opts.ChromePath); err != nil {
			fmt.Fprintf(os.Stderr, "warning: screenshots: %v\n", err)
		}
	}

	// ── summaries ──
	if cfg.Emit != "" {
		if err := report.Emit(os.Stdout, cfg.Emit, results); err != nil {
			fatal("emit: %v", err)
		}
	} else if cfg.Silent {
		for _, r := range results {
			fmt.Printf("%s subs=%d ports=%d live=%d takeovers=%d (%dms)\n",
				r.Target, len(r.Subdomains), len(r.Ports), len(r.Web),
				len(r.Takeovers), r.DurationMs)
		}
	} else if len(results) == 1 {
		ui.PrintTargetPanel(results[0])
	} else {
		ui.PrintBatchTable(results)
	}

	// ── save output ──
	if cfg.Output != "" {
		files, err := report.Save(cfg.Output, report.Format(cfg.Format), results)
		if err != nil {
			fatal("save: %v", err)
		}
		if !cfg.Silent {
			ui.PrintSaved(files)
		}
		if err := report.NotifyWebhook(ctx, cfg.Webhook, report.NewManifest(results)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: webhook: %v\n", err)
		}
	}
}

func runDiff(args []string) (bool, error) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	output := fs.String("o", "", "write JSON diff")
	webhook := fs.String("webhook", "", "notification webhook URL")
	if err := fs.Parse(args); err != nil {
		return false, err
	}
	if fs.NArg() != 2 {
		return false, fmt.Errorf("usage: nexprowl diff [-o diff.json] [-webhook URL] OLD NEW")
	}
	diff, err := report.ComparePaths(fs.Arg(0), fs.Arg(1))
	if err != nil {
		return false, err
	}
	fmt.Print(diff.String())
	if *output != "" {
		if err := report.WriteDiff(*output, diff); err != nil {
			return false, err
		}
	}
	if err := report.NotifyWebhook(context.Background(), *webhook, diff); err != nil {
		return false, err
	}
	return diff.Changed, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
