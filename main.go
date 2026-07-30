// dscan — all-in-one domain reconnaissance tool.
//
// Combines techniques from subfinder, gobuster, rustscan, httpx,
// wappalyzer, wafw00f, dnsrecon and subjack into one fast binary.
//
// Author: shadow0x0
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"dscan/internal/config"
	"dscan/internal/modules"
	"dscan/internal/report"
	"dscan/internal/scanner"
	"dscan/internal/ui"
)

func main() {
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
		fmt.Printf("dscan v%s by shadow0x0\n", scanner.Version)
		return
	}

	// ── UI setup ──
	var renderer *ui.UI
	var emit scanner.Emitter
	if !cfg.Silent {
		ui.Banner()
		ui.Boot()
		ui.ConfigLine(len(cfg.Targets), cfg.Modules, cfg.Opts.Workers,
			cfg.Opts.Concurrency, cfg.TimeoutS, cfg.Opts.Rate, len(cfg.Opts.Resolvers))
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

	// ── summaries ──
	if cfg.Silent {
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
		} else {
			for _, f := range files {
				fmt.Println("saved:", f)
			}
		}
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
