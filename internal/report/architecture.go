package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nexprowl/internal/scanner"
)

// ─── Mermaid architecture diagram ─────────────────────────
//
// Visualises one target's reconnaissance data as a layered mermaid
// flowchart (graph TD). The diagram is designed to be readable even for
// large scans by truncating each layer to a fixed ceiling and grouping
// related nodes in labelled subgraphs.
//
// Layers:
//   DNS Infrastructure  — NS, MX servers
//   Network             — resolved IPs with ASN / owner
//   Subdomains          — discovered hosts (top N)
//   Web Services        — live HTTP services, WAF/CDN shields
//   Security Findings   — takeover candidates, open zone transfers

// Truncation limits — keep the diagram readable.
const (
	archMaxNS   = 4
	archMaxMX   = 3
	archMaxIPs  = 8
	archMaxSubs = 12
	archMaxWeb  = 10
	archMaxTO   = 6
	archLabelW  = 40
)

type archGraph struct {
	Nodes []archNode
	Edges []archEdge
}

type archNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Class  string `json:"class,omitempty"`
	Parent string `json:"parent,omitempty"`
}

type archEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label,omitempty"`
	Class  string `json:"class,omitempty"`
}

// archBuilder accumulates nodes and edges with unique sequential IDs.
type archBuilder struct {
	graph  *archGraph
	ids    map[string]string
	next   int
	parent string
}

func newArchBuilder() *archBuilder {
	return &archBuilder{
		graph: &archGraph{},
		ids:   map[string]string{},
	}
}

// node declares a node once (dedup by key) and returns its ID.
func (b *archBuilder) node(key, label, class string) string {
	if id, ok := b.ids[key]; ok {
		return id
	}
	id := fmt.Sprintf("n%d", b.next)
	b.next++
	b.ids[key] = id
	b.graph.Nodes = append(b.graph.Nodes, archNode{
		ID:     id,
		Label:  label,
		Class:  class,
		Parent: b.parent,
	})
	return id
}

// diamond declares a diamond-shaped node {}.
func (b *archBuilder) diamond(key, label, class string) string {
	return b.node(key, label, class) // shape is handled by renderer class
}

func (b *archBuilder) edge(from, to, label string) {
	b.graph.Edges = append(b.graph.Edges, archEdge{Source: from, Target: to, Label: label})
}

func (b *archBuilder) dotEdge(from, to, label string) {
	b.graph.Edges = append(b.graph.Edges, archEdge{Source: from, Target: to, Label: label, Class: "dotted"})
}

func (b *archBuilder) linkEdge(from, to string) {
	b.graph.Edges = append(b.graph.Edges, archEdge{Source: from, Target: to, Class: "link"})
}

func (b *archBuilder) openSub(id, title string) {
	b.graph.Nodes = append(b.graph.Nodes, archNode{
		ID:    id,
		Label: title,
		Class: "group",
	})
	b.parent = id
}

func (b *archBuilder) closeSub() {
	b.parent = ""
}

// Mermaid renders the graph as a mermaid flowchart string.
func (g *archGraph) Mermaid() string {
	var b strings.Builder
	b.WriteString("graph TD\n")

	// Group nodes by parent
	children := make(map[string][]archNode)
	var roots []archNode
	for _, n := range g.Nodes {
		if n.Parent == "" {
			roots = append(roots, n)
		} else {
			children[n.Parent] = append(children[n.Parent], n)
		}
	}

	var writeNode func(n archNode, indent string)
	writeNode = func(n archNode, indent string) {
		if n.Class == "group" {
			fmt.Fprintf(&b, "%ssubgraph %s[\"%s\"]\n", indent, n.ID, mermaidSafe(n.Label))
			for _, child := range children[n.ID] {
				writeNode(child, indent+"  ")
			}
			fmt.Fprintf(&b, "%send\n", indent)
			return
		}
		shapeL, shapeR := "[", "]"
		if n.Class == "waf" {
			shapeL, shapeR = "{", "}"
		}
		class := ""
		if n.Class != "" {
			class = ":::" + n.Class
		}
		fmt.Fprintf(&b, "%s%s%s\"%s\"%s%s\n", indent, n.ID, shapeL, mermaidSafe(n.Label), shapeR, class)
	}

	for _, n := range roots {
		writeNode(n, "  ")
	}

	b.WriteString("\n")
	for _, e := range g.Edges {
		arr := "-->"
		if e.Class == "dotted" {
			arr = "-.->"
		} else if e.Class == "link" {
			arr = "---"
		}
		if e.Label != "" {
			fmt.Fprintf(&b, "  %s %s|%s| %s\n", e.Source, arr, mermaidSafe(e.Label), e.Target)
		} else {
			fmt.Fprintf(&b, "  %s %s %s\n", e.Source, arr, e.Target)
		}
	}

	defs := []string{
		"classDef root fill:#0b3542,stroke:#20d9ff,color:#d9f6ff,stroke-width:2px",
		"classDef dns fill:#122231,stroke:#20d9ff,color:#b9effa",
		"classDef net fill:#122231,stroke:#43e39f,color:#cdeede",
		"classDef sub fill:#0d1924,stroke:#4a6572,color:#dbe9f2",
		"classDef web fill:#122231,stroke:#ffca5c,color:#ffe3b0",
		"classDef waf fill:#231a10,stroke:#ffca5c,color:#ffca5c",
		"classDef danger fill:#33101c,stroke:#ff637d,color:#ffc2cc",
		"classDef group fill:transparent,stroke:#203548,stroke-width:1px,stroke-dasharray:5 5",
		"classDef muted fill:#0d1924,stroke:#2a3f4d,color:#718a99,stroke-dasharray:3",
	}
	b.WriteString("\n")
	for _, d := range defs {
		b.WriteString("  " + d + "\n")
	}
	return b.String()
}

// CytoscapeJSON renders the graph elements as a JSON array for Cytoscape.js.
func (g *archGraph) CytoscapeJSON() string {
	type cyData map[string]any
	type cyElement struct {
		Data    cyData `json:"data"`
		Classes string `json:"classes,omitempty"`
	}
	var elements []cyElement
	for _, n := range g.Nodes {
		d := cyData{"id": n.ID, "label": strings.ReplaceAll(n.Label, "<br/>", "\n")}
		if n.Parent != "" {
			d["parent"] = n.Parent
		}
		elements = append(elements, cyElement{Data: d, Classes: n.Class})
	}
	for i, e := range g.Edges {
		d := cyData{"id": fmt.Sprintf("e%d", i), "source": e.Source, "target": e.Target}
		if e.Label != "" {
			d["label"] = e.Label
		}
		elements = append(elements, cyElement{Data: d, Classes: e.Class})
	}
	out, _ := json.Marshal(elements)
	return string(out)
}

// ─── Diagram generation ───────────────────────────────────

// BuildArchitectureGraph builds the node/edge model for a target.
func BuildArchitectureGraph(r *scanner.Result) *archGraph {
	b := newArchBuilder()

	rootID := b.node("root", r.Target, "root")

	// ── DNS layer ─────────────────────────────────────────
	hasDNS := r.DNS != nil && (len(r.DNS.NS) > 0 || len(r.DNS.MX) > 0)
	if hasDNS {
		b.openSub("DNS", "DNS infrastructure")
		if len(r.DNS.NS) > 0 {
			label := "NS" + brList(r.DNS.NS, archMaxNS)
			nsID := b.node("dns:ns", label, "dns")
			_ = nsID
		}
		if len(r.DNS.MX) > 0 {
			label := "MX" + brList(r.DNS.MX, archMaxMX)
			mxID := b.node("dns:mx", label, "dns")
			_ = mxID
		}
		b.closeSub()
		b.linkEdge(rootID, "DNS")
	}

	// ── Network layer ─────────────────────────────────────
	ownerByIP := map[string]string{}
	for _, n := range r.Networks {
		short := archTrim(n.Owner, 24)
		if n.ASN != "" {
			ownerByIP[n.IP] = n.ASN + " · " + short
		} else {
			ownerByIP[n.IP] = short
		}
	}
	if len(r.IPs) > 0 {
		b.openSub("NET", "Network")
		shown := archCap(len(r.IPs), archMaxIPs)
		for _, ip := range r.IPs[:shown] {
			label := ip
			if info, ok := ownerByIP[ip]; ok {
				label += "<br/>" + info
			}
			b.node("ip:"+ip, label, "net")
		}
		if rest := len(r.IPs) - shown; rest > 0 {
			b.node("ip:more", fmt.Sprintf("+%d more", rest), "muted")
		}
		b.closeSub()
		b.edge(rootID, "NET", "resolves")
	}

	// ── Subdomains layer ──────────────────────────────────
	if len(r.Subdomains) > 0 {
		title := fmt.Sprintf("Subdomains · %d", len(r.Subdomains))
		b.openSub("SUBS", title)
		shown := archCap(len(r.Subdomains), archMaxSubs)
		for _, sub := range r.Subdomains[:shown] {
			b.node("sub:"+sub.Host, sub.Host, "sub")
		}
		if rest := len(r.Subdomains) - shown; rest > 0 {
			b.node("sub:more", fmt.Sprintf("+%d more", rest), "muted")
		}
		b.closeSub()
		b.linkEdge(rootID, "SUBS")
	}

	// ── Web services layer ────────────────────────────────
	if len(r.Web) > 0 {
		title := fmt.Sprintf("Web services · %d", len(r.Web))
		b.openSub("WEB", title)
		shown := archCap(len(r.Web), archMaxWeb)
		for _, w := range r.Web[:shown] {
			host := w.Host
			if host == "" {
				host = r.Target
			}
			label := host
			if w.Status > 0 {
				label += fmt.Sprintf("<br/>%d", w.Status)
			}
			if w.Server != "" {
				label += " · " + archTrim(w.Server, 16)
			}
			if len(w.Technologies) > 0 {
				label += "<br/>" + archTrim(strings.Join(w.Technologies, ", "), archLabelW)
			}
			webID := b.node("web:"+w.URL, label, "web")

			// WAF / CDN shield
			shield := w.WAF
			if shield == "" {
				shield = w.CDN
			}
			if shield != "" {
				wafID := b.diamond("waf:"+shield, shield, "waf")
				b.edge(webID, wafID, "behind")
			}

			// edge from subdomain or root
			if src, ok := b.ids["sub:"+host]; ok {
				b.edge(src, webID, "")
			} else if host != r.Target {
				if src, ok := b.ids["sub:"+host]; ok {
					b.edge(src, webID, "")
				}
			}
		}
		if rest := len(r.Web) - shown; rest > 0 {
			b.node("web:more", fmt.Sprintf("+%d more", rest), "muted")
		}
		b.closeSub()

		// root → web (for main-target web nodes without a subdomain edge)
		for _, w := range r.Web[:archCap(len(r.Web), archMaxWeb)] {
			host := w.Host
			if host == "" {
				host = r.Target
			}
			webID := b.ids["web:"+w.URL]
			if host == r.Target {
				b.edge(rootID, webID, "")
			}
		}
	}

	// ── Security findings ─────────────────────────────────
	hasSec := len(r.Takeovers) > 0 || len(r.ZoneTransfer) > 0
	if hasSec {
		b.openSub("SEC", "Security findings")
		shown := archCap(len(r.Takeovers), archMaxTO)
		for _, t := range r.Takeovers[:shown] {
			label := t.Host + "<br/>" + t.Service + "<br/>" + archTrim(t.CNAME, 32)
			toID := b.node("to:"+t.Host, label, "danger")
			if src, ok := b.ids["sub:"+t.Host]; ok {
				b.dotEdge(src, toID, "dangling")
			} else {
				b.dotEdge(rootID, toID, "dangling")
			}
		}
		for _, z := range r.ZoneTransfer {
			label := fmt.Sprintf("AXFR open<br/>%s<br/>%d records", archTrim(z.Server, 28), len(z.Records))
			b.node("axfr:"+z.Server, label, "danger")
		}
		b.closeSub()
	}

	return b.graph
}

// ─── Markdown document ────────────────────────────────────

// ArchitectureMarkdown renders a standalone architecture.md with one
// mermaid diagram per target plus a brief summary table.
func ArchitectureMarkdown(results []*scanner.Result, generated time.Time) string {
	var b strings.Builder
	b.WriteString("# Target architecture\n\n")
	fmt.Fprintf(&b, "> Generated by **NexProwl** · %s\n\n", generated.Format("02 Jan 2006, 15:04 MST"))
	b.WriteString("**Legend:** ")
	b.WriteString("Blue = DNS · Green = Network / IP · Grey = Subdomain · ")
	b.WriteString("Amber = Web service · Diamond = WAF/CDN · Red = Security finding\n")

	for _, r := range results {
		fmt.Fprintf(&b, "\n---\n\n## `%s`\n\n", r.Target)
		fmt.Fprintf(&b, "- **IPs:** %s\n", orDash(strings.Join(r.IPs, ", ")))
		fmt.Fprintf(&b, "- **Subdomains:** %d\n", len(r.Subdomains))
		fmt.Fprintf(&b, "- **Web services:** %d\n", len(r.Web))
		fmt.Fprintf(&b, "- **Open ports:** %d\n", len(r.Ports))
		if len(r.Takeovers) > 0 {
			fmt.Fprintf(&b, "- **Takeover candidates:** %d\n", len(r.Takeovers))
		}
		if len(r.ZoneTransfer) > 0 {
			fmt.Fprintf(&b, "- **Zone transfers:** %d\n", len(r.ZoneTransfer))
		}
		b.WriteString("\n```mermaid\n")
		b.WriteString(BuildArchitectureGraph(r).Mermaid())
		b.WriteString("\n```\n")
	}
	return b.String()
}

func writeArchitectureMD(path string, results []*scanner.Result) error {
	return os.WriteFile(path, []byte(ArchitectureMarkdown(results, time.Now())), 0644)
}

// architectureCompanionPath derives the architecture.md path from a
// single-file output path: "results/out.html" → "results/out-architecture.md".
func architectureCompanionPath(outPath string) string {
	ext := filepath.Ext(outPath)
	return strings.TrimSuffix(outPath, ext) + "-architecture.md"
}

// ─── Helpers ──────────────────────────────────────────────

// mermaidSafe escapes text for a quoted mermaid node label.
// Target-controlled data (hostnames, banners, titles) may contain
// characters that break the diagram or enable injection. Our own
// <br/> line-break markers are preserved.
func mermaidSafe(s string) string {
	// protect our own <br/> markers from the angle-bracket replacement
	const marker = "\x00BR\x00"
	s = strings.ReplaceAll(s, "<br/>", marker)
	s = strings.NewReplacer(
		`"`, "'",
		`\`, "/",
		"`", "'",
		"<", "(",
		">", ")",
		"&", "+",
	).Replace(s)
	s = strings.ReplaceAll(s, marker, "<br/>")
	return strings.TrimSpace(s)
}

// brList formats a string slice as <br/>-separated lines, capped at max
// entries. Returns "" if the slice is empty.
func brList(items []string, max int) string {
	if len(items) == 0 {
		return ""
	}
	n := archCap(len(items), max)
	var b strings.Builder
	for _, item := range items[:n] {
		b.WriteString("<br/>")
		b.WriteString(mermaidSafe(archTrim(item, archLabelW)))
	}
	if rest := len(items) - n; rest > 0 {
		fmt.Fprintf(&b, "<br/>+%d more", rest)
	}
	return b.String()
}

// archTrim returns s truncated to maxRunes with a trailing "…".
func archTrim(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes-1]) + "…"
}

// archCap returns min(total, max).
func archCap(total, max int) int {
	if total < max {
		return total
	}
	return max
}
