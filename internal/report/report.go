// Package report writes scan results in multiple structured formats.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"nexprowl/internal/scanner"
)

// Format is an output format identifier.
type Format string

const (
	FormatJSON  Format = "json"
	FormatJSONL Format = "jsonl"
	FormatCSV   Format = "csv"
	FormatMD    Format = "md"
	FormatHTML  Format = "html"
	FormatTXT   Format = "txt"
)

// InferFormat derives the format from a file extension.
func InferFormat(path string) Format {
	switch strings.ToLower(strings.TrimPrefix(filepath.Ext(path), ".")) {
	case "jsonl", "ndjson":
		return FormatJSONL
	case "csv":
		return FormatCSV
	case "md", "markdown":
		return FormatMD
	case "html", "htm":
		return FormatHTML
	case "txt":
		return FormatTXT
	default:
		return FormatJSON
	}
}

// Save decides file-vs-directory mode from the -o path:
//   - path with extension (.json/.jsonl/.csv/.md/.html/.txt) → one combined file
//   - path without extension → directory: per-target files + summary.csv
//
// format overrides the extension when set.
func Save(path string, format Format, results []*scanner.Result) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	ext := filepath.Ext(path)
	if ext != "" {
		if format == "" {
			format = InferFormat(path)
		}
		if dir := filepath.Dir(path); dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, err
			}
		}
		if err := writeCombined(path, format, results); err != nil {
			return nil, err
		}
		written := []string{path}
		archPath := architectureCompanionPath(path)
		if err := writeArchitectureMD(archPath, results); err != nil {
			return written, err
		}
		written = append(written, archPath)
		return written, nil
	}

	// directory mode
	if format == "" {
		format = FormatJSON
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, err
	}
	var written []string
	for _, r := range results {
		name := sanitizeFileName(r.Target) + "." + string(format)
		fp := filepath.Join(path, name)
		if err := writeCombined(fp, format, []*scanner.Result{r}); err != nil {
			return written, err
		}
		written = append(written, fp)
	}
	summary := filepath.Join(path, "summary.csv")
	if err := writeCSV(summary, results); err != nil {
		return written, err
	}
	written = append(written, summary)

	htmlReport := filepath.Join(path, "report.html")
	if err := writeHTML(htmlReport, results); err != nil {
		return written, err
	}
	written = append(written, htmlReport)

	archReport := filepath.Join(path, "architecture.md")
	if err := writeArchitectureMD(archReport, results); err != nil {
		return written, err
	}
	written = append(written, archReport)

	manifestPath := filepath.Join(path, "manifest.json")
	if err := writeManifest(manifestPath, NewManifest(results)); err != nil {
		return written, err
	}
	written = append(written, manifestPath)

	artifacts := map[string][]string{
		"subdomains.txt": collect(results, "subdomains"),
		"urls.txt":       collect(results, "urls"),
		"hostports.txt":  collect(results, "hostports"),
		"endpoints.txt":  collect(results, "endpoints"),
		"ips.txt":        collect(results, "ips"),
	}
	for name, lines := range artifacts {
		fp := filepath.Join(path, name)
		content := strings.Join(lines, "\n")
		if content != "" {
			content += "\n"
		}
		if err := os.WriteFile(fp, []byte(content), 0644); err != nil {
			return written, err
		}
		written = append(written, fp)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "latest.txt"), []byte(filepath.Base(path)+"\n"), 0644); err == nil {
		written = append(written, filepath.Join(filepath.Dir(path), "latest.txt"))
	}
	return written, nil
}

func writeCombined(path string, format Format, results []*scanner.Result) error {
	switch format {
	case FormatJSONL:
		return writeJSONL(path, results)
	case FormatCSV:
		return writeCSV(path, results)
	case FormatMD:
		return writeMarkdown(path, results)
	case FormatHTML:
		return writeHTML(path, results)
	case FormatTXT:
		return writeText(path, results)
	default:
		return writeJSON(path, results)
	}
}

// ─── JSON ─────────────────────────────────────────────────

func writeJSON(path string, results []*scanner.Result) error {
	var v any = results
	if len(results) == 1 {
		v = results[0]
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func writeJSONL(path string, results []*scanner.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

// ─── CSV ──────────────────────────────────────────────────

func writeCSV(path string, results []*scanner.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"target", "host", "ips", "cname", "url", "status", "title",
		"server", "technologies", "waf", "cdn", "open_ports", "source",
	}); err != nil {
		return err
	}

	for _, r := range results {
		portsByHost := map[string][]string{}
		for _, p := range r.Ports {
			host := p.Host
			if host == "" {
				host = r.Target
			}
			portsByHost[host] = append(portsByHost[host], fmt.Sprint(p.Port))
		}
		webByHost := map[string][]scanner.WebResult{}
		for _, wr := range r.Web {
			host := wr.Host
			if host == "" {
				host = r.Target
			}
			webByHost[host] = append(webByHost[host], wr)
		}

		writeRow := func(host string, ips []string, cname, source string, wr *scanner.WebResult) {
			row := []string{
				r.Target, host, strings.Join(ips, "|"), cname,
				"", "", "", "", "", "", "", strings.Join(portsByHost[host], "|"), source,
			}
			if wr != nil {
				row[4] = wr.URL
				row[5] = fmt.Sprint(wr.Status)
				row[6] = wr.Title
				row[7] = wr.Server
				row[8] = strings.Join(wr.Technologies, "|")
				row[9] = wr.WAF
				row[10] = wr.CDN
			}
			_ = w.Write(row)
		}
		writeHost := func(host string, ips []string, cname, source string) {
			web := webByHost[host]
			if len(web) == 0 {
				writeRow(host, ips, cname, source, nil)
				return
			}
			for i := range web {
				writeRow(host, ips, cname, source, &web[i])
			}
		}

		writeHost(r.Target, r.IPs, "", "main")
		for _, sub := range r.Subdomains {
			writeHost(sub.Host, sub.IPs, sub.CNAME, sub.Source)
		}
		for _, vhost := range r.VHosts {
			if _, known := webByHost[vhost.Host]; known {
				continue
			}
			writeHost(vhost.Host, nil, "", "vhost")
		}
	}
	return w.Error()
}

// ─── Markdown ─────────────────────────────────────────────

func writeMarkdown(path string, results []*scanner.Result) error {
	var b strings.Builder
	b.WriteString("# NexProwl recon report\n\n")

	totalSubs, totalPorts, totalLive, totalTakeovers := 0, 0, 0, 0
	for _, r := range results {
		totalSubs += len(r.Subdomains)
		totalPorts += len(r.Ports)
		totalLive += len(r.Web)
		totalTakeovers += len(r.Takeovers)
	}
	fmt.Fprintf(&b, "| targets | subdomains | open ports | live web | takeover candidates |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d |\n\n",
		len(results), totalSubs, totalPorts, totalLive, totalTakeovers)

	for _, r := range results {
		fmt.Fprintf(&b, "\n## `%s`\n\n", r.Target)
		fmt.Fprintf(&b, "- **IPs:** %s\n", orDash(strings.Join(r.IPs, ", ")))
		fmt.Fprintf(&b, "- **Duration:** %d ms\n", r.DurationMs)
		if r.Error != "" {
			fmt.Fprintf(&b, "- **Errors:** %s\n", r.Error)
		}

		if r.DNS != nil {
			b.WriteString("\n### DNS\n\n")
			b.WriteString("| record | values |\n|---|---|\n")
			writeDNSRow := func(name string, vals []string) {
				if len(vals) > 0 {
					fmt.Fprintf(&b, "| %s | %s |\n", name, mdCell(strings.Join(vals, ", ")))
				}
			}
			writeDNSRow("A", r.DNS.A)
			writeDNSRow("AAAA", r.DNS.AAAA)
			writeDNSRow("MX", r.DNS.MX)
			writeDNSRow("NS", r.DNS.NS)
			writeDNSRow("CAA", r.DNS.CAA)
			writeDNSRow("SOA", r.DNS.SOA)
			writeDNSRow("SRV", r.DNS.SRV)
			writeDNSRow("PTR", r.DNS.PTR)
			writeDNSRow("SPF", r.DNS.SPF)
			writeDNSRow("DMARC", r.DNS.DMARC)
			if r.DNS.CNAME != "" {
				fmt.Fprintf(&b, "| CNAME | %s |\n", mdCell(r.DNS.CNAME))
			}
		}

		if len(r.ZoneTransfer) > 0 {
			b.WriteString("\n### ⚠️ Zone transfer (AXFR)\n\n")
			for _, z := range r.ZoneTransfer {
				fmt.Fprintf(&b, "**%s** — %d records:\n\n```\n", z.Server, len(z.Records))
				for _, rec := range z.Records {
					b.WriteString(rec + "\n")
				}
				b.WriteString("```\n")
			}
		}

		if len(r.VHosts) > 0 {
			b.WriteString("\n### Virtual hosts\n\n")
			b.WriteString("| host | status | size | title |\n|---|---|---|---|\n")
			for _, v := range r.VHosts {
				fmt.Fprintf(&b, "| %s | %d | %d | %s |\n", mdCell(v.Host), v.Status, v.Size, mdCell(v.Title))
			}
		}

		if len(r.Ports) > 0 {
			b.WriteString("\n### Open ports\n\n")
			b.WriteString("| host | ip | port | service | banner |\n|---|---|---|---|---|\n")
			for _, p := range r.Ports {
				fmt.Fprintf(&b, "| %s | %s | %d | %s | %s |\n",
					mdCell(p.Host), p.IP, p.Port, p.Service, mdCell(p.Banner))
			}
		}

		if len(r.Web) > 0 {
			b.WriteString("\n### Live web services\n\n")
			b.WriteString("| url | status | title | server | tech | waf | screenshot |\n|---|---|---|---|---|---|---|\n")
			for _, w := range r.Web {
				screenshot := ""
				if w.Screenshot != "" {
					screenshot = "[view](" + w.Screenshot + ")"
				}
				fmt.Fprintf(&b, "| %s | %d | %s | %s | %s | %s | %s |\n",
					mdCell(w.URL), w.Status, mdCell(w.Title), mdCell(w.Server),
					mdCell(strings.Join(w.Technologies, ", ")), mdCell(w.WAF), screenshot)
			}
		}

		if len(r.Subdomains) > 0 {
			b.WriteString("\n### Subdomains\n\n")
			b.WriteString("| host | ips | cname | source |\n|---|---|---|---|\n")
			for _, s := range r.Subdomains {
				fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
					mdCell(s.Host), strings.Join(s.IPs, ", "), mdCell(s.CNAME), s.Source)
			}
		}

		if r.TLS != nil {
			b.WriteString("\n### TLS\n\n")
			fmt.Fprintf(&b, "- **Version:** %s (%s)\n", r.TLS.Version, r.TLS.Cipher)
			fmt.Fprintf(&b, "- **Issuer:** %s\n", r.TLS.Issuer)
			exp := ""
			if r.TLS.Expired {
				exp = " — **EXPIRED**"
			}
			fmt.Fprintf(&b, "- **Validity:** %s → %s%s\n", r.TLS.ValidFrom, r.TLS.ValidTo, exp)
		}

		if len(r.Endpoints) > 0 {
			b.WriteString("\n### Endpoints\n\n")
			b.WriteString("| url | source | depth |\n|---|---|---|\n")
			for _, endpoint := range r.Endpoints {
				fmt.Fprintf(&b, "| %s | %s | %d |\n", mdCell(endpoint.URL), endpoint.Source, endpoint.Depth)
			}
		}

		if len(r.Networks) > 0 {
			b.WriteString("\n### Network ownership\n\n")
			b.WriteString("| ip | asn | prefix | owner |\n|---|---|---|---|\n")
			for _, network := range r.Networks {
				fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
					network.IP, network.ASN, network.Prefix, mdCell(network.Owner))
			}
		}

		if len(r.Sources) > 0 {
			b.WriteString("\n### Passive sources\n\n")
			b.WriteString("| source | found | duration | error |\n|---|---|---|---|\n")
			for _, source := range r.Sources {
				fmt.Fprintf(&b, "| %s | %d | %d ms | %s |\n",
					source.Name, source.Found, source.DurationMs, mdCell(source.Error))
			}
		}

		if len(r.Takeovers) > 0 {
			b.WriteString("\n### ⚠️ Takeover candidates\n\n")
			b.WriteString("| host | cname | service |\n|---|---|---|\n")
			for _, t := range r.Takeovers {
				fmt.Fprintf(&b, "| %s | %s | %s |\n", mdCell(t.Host), mdCell(t.CNAME), t.Service)
			}
		}
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

// ─── Plain text ───────────────────────────────────────────

func writeText(path string, results []*scanner.Result) error {
	var b strings.Builder
	for _, r := range results {
		fmt.Fprintf(&b, "═══ %s (%d ms)\n", r.Target, r.DurationMs)
		fmt.Fprintf(&b, "  ips:        %s\n", orDash(strings.Join(r.IPs, ", ")))
		fmt.Fprintf(&b, "  subdomains: %d\n", len(r.Subdomains))
		var ps []string
		for _, p := range r.Ports {
			ps = append(ps, fmt.Sprint(p.Port))
		}
		fmt.Fprintf(&b, "  open ports: %s\n", orDash(strings.Join(ps, ",")))
		fmt.Fprintf(&b, "  live web:   %d\n", len(r.Web))
		if len(r.Web) > 0 {
			w := r.Web[0]
			fmt.Fprintf(&b, "  main site:  %d %q [%s]\n", w.Status, w.Title, strings.Join(w.Technologies, ", "))
			if w.WAF != "" {
				fmt.Fprintf(&b, "  waf:        %s\n", w.WAF)
			}
		}
		if r.TLS != nil {
			exp := ""
			if r.TLS.Expired {
				exp = " EXPIRED"
			}
			fmt.Fprintf(&b, "  tls:        %s, valid to %s%s\n", r.TLS.Version, r.TLS.ValidTo, exp)
		}
		for _, z := range r.ZoneTransfer {
			fmt.Fprintf(&b, "  axfr:       %s — %d records dumped!\n", z.Server, len(z.Records))
		}
		for _, v := range r.VHosts {
			fmt.Fprintf(&b, "  vhost:      %s → %d (%db) %s\n", v.Host, v.Status, v.Size, v.Title)
		}
		for _, t := range r.Takeovers {
			fmt.Fprintf(&b, "  takeover?:  %s → %s (%s)\n", t.Host, t.CNAME, t.Service)
		}
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}

// ─── helpers ──────────────────────────────────────────────

func sanitizeFileName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}

// mdCell escapes a value for a markdown table cell. Titles, banners and
// server headers come from the scanned host, so an unescaped "|" lets a
// target corrupt the report layout.
var mdCellEscaper = strings.NewReplacer("|", `\|`, "\n", " ", "\r", " ")

func mdCell(s string) string { return mdCellEscaper.Replace(s) }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Emit writes one machine-friendly finding per line.
func Emit(w io.Writer, mode string, results []*scanner.Result) error {
	if mode == "jsonl" {
		enc := json.NewEncoder(w)
		for _, r := range results {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	}
	for _, value := range collect(results, mode) {
		if _, err := fmt.Fprintln(w, value); err != nil {
			return err
		}
	}
	return nil
}

func collect(results []*scanner.Result, mode string) []string {
	var values []string
	for _, r := range results {
		switch mode {
		case "subdomains":
			for _, sub := range r.Subdomains {
				values = append(values, sub.Host)
			}
		case "urls":
			for _, web := range r.Web {
				values = append(values, web.URL)
			}
		case "hostports":
			for _, port := range r.Ports {
				host := port.Host
				if host == "" {
					host = r.Target
				}
				values = append(values, net.JoinHostPort(host, fmt.Sprint(port.Port)))
			}
		case "ips":
			values = append(values, r.IPs...)
			if r.DNS != nil {
				values = append(values, r.DNS.AAAA...)
			}
			for _, sub := range r.Subdomains {
				values = append(values, sub.IPs...)
			}
		case "endpoints":
			for _, endpoint := range r.Endpoints {
				values = append(values, endpoint.URL)
			}
		}
	}
	return scanner.UniqueSorted(values)
}
