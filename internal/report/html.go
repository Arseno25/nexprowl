package report

import (
	"html/template"
	"os"
	"strings"
	"time"

	"nexprowl/internal/scanner"
)

type htmlReportData struct {
	Results   []*scanner.Result
	Generated string
	Subs      int
	Ports     int
	Live      int
	Endpoints int
	Takeovers int
}

func writeHTML(path string, results []*scanner.Result) error {
	data := htmlReportData{
		Results:   results,
		Generated: time.Now().Format("02 Jan 2006, 15:04 MST"),
	}
	for _, r := range results {
		data.Subs += len(r.Subdomains)
		data.Ports += len(r.Ports)
		data.Live += len(r.Web)
		data.Endpoints += len(r.Endpoints)
		data.Takeovers += len(r.Takeovers)
	}

	t, err := template.New("report").Funcs(template.FuncMap{
		"join": strings.Join,
		"dash": orDash,
		"statusClass": func(status int) string {
			switch {
			case status >= 200 && status < 300:
				return "ok"
			case status >= 300 && status < 400:
				return "redirect"
			default:
				return "bad"
			}
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, data)
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexProwl reconnaissance report</title>
<style>
:root{color-scheme:dark;--bg:#071018;--surface:#0d1924;--surface2:#122231;--line:#203548;--text:#e8f1f7;--muted:#8fa6b8;--cyan:#20d9ff;--green:#43e39f;--amber:#ffca5c;--red:#ff637d}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(circle at 90% 0,#12334b 0,transparent 30rem),var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{width:min(1180px,calc(100% - 32px));margin:auto;padding:48px 0 80px}
header{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:28px}
.eyebrow{color:var(--cyan);font:700 12px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.16em;text-transform:uppercase}
h1{margin:6px 0 2px;font-size:clamp(28px,5vw,48px);line-height:1.05;letter-spacing:-.04em}
h2{margin:0;font-size:22px;overflow-wrap:anywhere}
h3{margin:0 0 14px;font-size:15px;color:#cce0ed;letter-spacing:.02em}
.muted{color:var(--muted)}
.summary,.target-stats{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}
.metric,.panel,.target{background:linear-gradient(145deg,rgba(18,34,49,.96),rgba(10,23,34,.96));border:1px solid var(--line);box-shadow:0 18px 60px rgba(0,0,0,.18)}
.metric{padding:18px;border-radius:14px}
.metric strong{display:block;font-size:26px;line-height:1.1}
.metric span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.target{margin-top:28px;border-radius:18px;overflow:hidden}
.target-head{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;padding:24px;border-bottom:1px solid var(--line)}
.chips{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:7px}
.chip,.status{display:inline-flex;align-items:center;border-radius:999px;padding:4px 9px;background:#172a3a;color:#bdd1df;font:600 12px/1.3 ui-monospace,SFMono-Regular,Consolas,monospace}
.chip.accent{background:rgba(32,217,255,.12);color:var(--cyan)}
.target-stats{grid-template-columns:repeat(4,1fr);padding:16px 24px;border-bottom:1px solid var(--line)}
.target-stats div{color:var(--muted)}
.target-stats strong{display:block;color:var(--text);font-size:19px}
.content{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;padding:20px}
.panel{min-width:0;padding:18px;border-radius:13px;box-shadow:none}
.panel.wide{grid-column:1/-1}
.alert{margin:20px 20px 0;padding:12px 14px;border:1px solid rgba(255,99,125,.5);border-radius:10px;background:rgba(255,99,125,.08);color:#ffc2cc}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
tr:last-child td{border-bottom:0}
code{color:#b9effa;font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}
a{color:var(--cyan);text-decoration:none} a:hover{text-decoration:underline}
.status.ok{background:rgba(67,227,159,.13);color:var(--green)}
.status.redirect{background:rgba(255,202,92,.13);color:var(--amber)}
.status.bad{background:rgba(255,99,125,.13);color:var(--red)}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:8px 16px;margin:0}
.kv dt{color:var(--muted)}.kv dd{margin:0;overflow-wrap:anywhere}
.records{max-height:260px;overflow:auto;margin:8px 0 0;padding:12px;border-radius:8px;background:#071018;color:#b9cad6;white-space:pre-wrap}
footer{padding-top:26px;text-align:center;color:var(--muted);font-size:12px}
@media(max-width:800px){main{width:min(100% - 20px,1180px);padding-top:28px}header,.target-head{display:block}.chips{justify-content:flex-start;margin-top:14px}.summary{grid-template-columns:repeat(2,1fr)}.summary .metric:first-child{grid-column:1/-1}.content{grid-template-columns:1fr}.panel.wide{grid-column:auto}}
@media(max-width:520px){.target-stats{grid-template-columns:repeat(2,1fr)}.summary{grid-template-columns:1fr}.summary .metric:first-child{grid-column:auto}.content{padding:12px}.target-head{padding:18px}}
@media print{:root{color-scheme:light;--bg:#fff;--surface:#fff;--surface2:#fff;--line:#d9e0e5;--text:#16232d;--muted:#536875}body{background:#fff}.target,.metric,.panel{box-shadow:none}.target{break-inside:avoid}main{width:100%;padding:0}}
</style>
</head>
<body>
<main>
<header>
  <div><div class="eyebrow">NexProwl / reconnaissance</div><h1>Scan report</h1><div class="muted">Generated {{.Generated}}</div></div>
  <div class="muted">Standalone HTML · ready to share or print</div>
</header>

<section class="summary" aria-label="Scan summary">
  <div class="metric"><strong>{{len .Results}}</strong><span>Targets</span></div>
  <div class="metric"><strong>{{.Subs}}</strong><span>Subdomains</span></div>
  <div class="metric"><strong>{{.Ports}}</strong><span>Open ports</span></div>
  <div class="metric"><strong>{{.Live}}</strong><span>Live web</span></div>
  <div class="metric"><strong>{{.Endpoints}}</strong><span>Endpoints</span></div>
  <div class="metric"><strong>{{.Takeovers}}</strong><span>Takeovers</span></div>
</section>

{{range .Results}}
<article class="target">
  <div class="target-head">
    <div><div class="eyebrow">Target</div><h2>{{.Target}}</h2></div>
    <div class="chips">
      <span class="chip accent">{{.DurationMs}} ms</span>
      {{range .IPs}}<span class="chip">{{.}}</span>{{end}}
    </div>
  </div>
  {{if .Error}}<div class="alert"><strong>Scan error:</strong> {{.Error}}</div>{{end}}
  {{if or .Takeovers .ZoneTransfer}}<div class="alert"><strong>Attention required:</strong> {{len .Takeovers}} takeover candidate(s), {{len .ZoneTransfer}} successful zone transfer(s).</div>{{end}}
  <div class="target-stats">
    <div><strong>{{len .Subdomains}}</strong>subdomains</div>
    <div><strong>{{len .Ports}}</strong>open ports</div>
    <div><strong>{{len .Web}}</strong>web services</div>
    <div><strong>{{len .VHosts}}</strong>virtual hosts</div>
  </div>

  <div class="content">
    {{with .DNS}}
    <section class="panel">
      <h3>DNS records</h3>
      <dl class="kv">
        {{if .A}}<dt>A</dt><dd><code>{{join .A ", "}}</code></dd>{{end}}
        {{if .AAAA}}<dt>AAAA</dt><dd><code>{{join .AAAA ", "}}</code></dd>{{end}}
        {{if .MX}}<dt>MX</dt><dd>{{join .MX ", "}}</dd>{{end}}
        {{if .NS}}<dt>NS</dt><dd>{{join .NS ", "}}</dd>{{end}}
        {{if .TXT}}<dt>TXT</dt><dd>{{join .TXT ", "}}</dd>{{end}}
        {{if .CAA}}<dt>CAA</dt><dd>{{join .CAA ", "}}</dd>{{end}}
        {{if .SOA}}<dt>SOA</dt><dd>{{join .SOA ", "}}</dd>{{end}}
        {{if .SRV}}<dt>SRV</dt><dd>{{join .SRV ", "}}</dd>{{end}}
        {{if .PTR}}<dt>PTR</dt><dd>{{join .PTR ", "}}</dd>{{end}}
        {{if .SPF}}<dt>SPF</dt><dd>{{join .SPF ", "}}</dd>{{end}}
        {{if .DMARC}}<dt>DMARC</dt><dd>{{join .DMARC ", "}}</dd>{{end}}
        {{if .CNAME}}<dt>CNAME</dt><dd>{{.CNAME}}</dd>{{end}}
      </dl>
    </section>
    {{end}}

    {{with .TLS}}
    <section class="panel">
      <h3>TLS certificate</h3>
      <dl class="kv">
        <dt>Version</dt><dd>{{dash .Version}} · {{dash .Cipher}}</dd>
        <dt>Issuer</dt><dd>{{dash .Issuer}}</dd>
        <dt>Subject</dt><dd>{{dash .Subject}}</dd>
        <dt>Validity</dt><dd>{{.ValidFrom}} → {{.ValidTo}} {{if .Expired}}<span class="status bad">expired</span>{{end}}</dd>
        {{if .SANs}}<dt>SANs</dt><dd>{{join .SANs ", "}}</dd>{{end}}
      </dl>
    </section>
    {{end}}

    {{if .Web}}
    <section class="panel wide">
      <h3>Live web services</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Technology</th><th>WAF / CDN</th><th>Evidence</th></tr></thead>
        <tbody>{{range .Web}}<tr>
          <td><a href="{{.URL}}" target="_blank" rel="noreferrer">{{.URL}}</a></td>
          <td><span class="status {{statusClass .Status}}">{{.Status}}</span></td>
          <td>{{dash .Title}}</td><td>{{dash .Server}}</td>
          <td>{{dash (join .Technologies ", ")}}</td><td>{{dash .WAF}}{{if .CDN}} / {{.CDN}}{{end}}</td>
          <td>{{if .Screenshot}}<a href="{{.Screenshot}}">screenshot</a>{{else}}—{{end}}</td>
        </tr>{{end}}</tbody>
      </table></div>
    </section>
    {{end}}

    {{if .Ports}}
    <section class="panel">
      <h3>Open ports</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Host / IP</th><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
        <tbody>{{range .Ports}}<tr><td><code>{{.Host}}{{if .IP}} / {{.IP}}{{end}}</code></td><td><code>{{.Port}}</code></td><td>{{dash .Service}}</td><td>{{dash .Banner}}</td></tr>{{end}}</tbody>
      </table></div>
    </section>
    {{end}}

    {{if .VHosts}}
    <section class="panel">
      <h3>Virtual hosts</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Host</th><th>Status</th><th>Size</th><th>Title</th></tr></thead>
        <tbody>{{range .VHosts}}<tr><td><code>{{.Host}}</code></td><td><span class="status {{statusClass .Status}}">{{.Status}}</span></td><td>{{.Size}} B</td><td>{{dash .Title}}</td></tr>{{end}}</tbody>
      </table></div>
    </section>
    {{end}}

    {{if .Subdomains}}
    <section class="panel wide">
      <h3>Subdomains</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Host</th><th>IPs</th><th>CNAME</th><th>Source</th></tr></thead>
        <tbody>{{range .Subdomains}}<tr><td><code>{{.Host}}</code></td><td>{{dash (join .IPs ", ")}}</td><td>{{dash .CNAME}}</td><td>{{.Source}}</td></tr>{{end}}</tbody>
      </table></div>
    </section>
    {{end}}

    {{if .Endpoints}}
    <section class="panel wide">
      <h3>Discovered endpoints</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>URL</th><th>Source</th><th>Depth</th></tr></thead>
        <tbody>{{range .Endpoints}}<tr><td><a href="{{.URL}}" target="_blank" rel="noreferrer">{{.URL}}</a></td><td>{{.Source}}</td><td>{{.Depth}}</td></tr>{{end}}</tbody>
      </table></div>
    </section>
    {{end}}

    {{if .Networks}}
    <section class="panel">
      <h3>Network ownership</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>IP</th><th>ASN</th><th>Prefix</th><th>Owner</th></tr></thead>
        <tbody>{{range .Networks}}<tr><td><code>{{.IP}}</code></td><td>{{.ASN}}</td><td>{{.Prefix}}</td><td>{{.Owner}}</td></tr>{{end}}</tbody>
      </table></div>
    </section>
    {{end}}

    {{if .Sources}}
    <section class="panel">
      <h3>Passive source health</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Source</th><th>Found</th><th>Duration</th><th>Error</th></tr></thead>
        <tbody>{{range .Sources}}<tr><td>{{.Name}}</td><td>{{.Found}}</td><td>{{.DurationMs}} ms</td><td>{{dash .Error}}</td></tr>{{end}}</tbody>
      </table></div>
    </section>
    {{end}}

    {{if .TLSHosts}}
    <section class="panel wide">
      <h3>TLS endpoints</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Host</th><th>Port</th><th>Version</th><th>Issuer</th><th>Days left</th><th>Mismatch</th></tr></thead>
        <tbody>{{range .TLSHosts}}<tr><td><code>{{.Host}}</code></td><td>{{.Port}}</td><td>{{.Version}}</td><td>{{.Issuer}}</td><td>{{.DaysLeft}}</td><td>{{if .Mismatch}}yes{{else}}no{{end}}</td></tr>{{end}}</tbody>
      </table></div>
    </section>
    {{end}}

    {{if .Takeovers}}
    <section class="panel wide">
      <h3>Takeover candidates</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Host</th><th>CNAME</th><th>Service</th><th>Note</th></tr></thead>
        <tbody>{{range .Takeovers}}<tr><td><code>{{.Host}}</code></td><td>{{.CNAME}}</td><td>{{.Service}}</td><td>{{.Note}}</td></tr>{{end}}</tbody>
      </table></div>
    </section>
    {{end}}

    {{range .ZoneTransfer}}
    <section class="panel wide">
      <h3>Zone transfer · {{.Server}}</h3>
      <div class="muted">{{len .Records}} records returned</div>
      <pre class="records">{{range .Records}}{{.}}
{{end}}</pre>
    </section>
    {{end}}
  </div>
</article>
{{end}}

<footer>NexProwl · all-in-one domain reconnaissance · by shadow0x0</footer>
</main>
</body>
</html>
`
