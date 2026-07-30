package detect

// techSignatures — wappalyzer/whatweb technique: match headers + HTML body.
var techSignatures = []signature{
	// Web servers
	sig("Nginx", `nginx`),
	sig("Apache", `apache`),
	sig("IIS", `microsoft-iis`),
	sig("Tomcat", `apache-coyote|tomcat`),
	sig("Jetty", `jetty`),
	sig("Node.js", `node\.?js`),
	sig("Express", `x-powered-by: express`),
	sig("Gunicorn", `gunicorn`),
	sig("Caddy", `caddy`),
	sig("OpenResty", `openresty`),
	sig("LiteSpeed", `litespeed`),
	sig("Lighttpd", `lighttpd`),
	sig("Envoy", `envoy`),
	sig("Kestrel", `kestrel`),

	// Languages / frameworks
	sig("PHP", `x-powered-by: php|phpsessid|\.php["'?\s]`),
	sig("ASP.NET", `__viewstate|__eventvalidation|asp\.net_sessionid|x-aspnet-version`),
	sig("Laravel", `laravel_session`),
	sig("CodeIgniter", `ci_session`),
	sig("Django", `csrftoken|django\.session`),
	sig("Ruby on Rails", `_rails_session|csrf-param`),
	sig("Spring", `jsessionid|x-application-context`),
	sig("Flask", `werkzeug`),

	// CMS
	sig("WordPress", `/wp-(content|includes|admin)/|wp-json|name="generator" content="wordpress`),
	sig("WooCommerce", `/wp-content/plugins/woocommerce|woocommerce`),
	sig("Joomla", `/components/com_|/modules/mod_|content="joomla`),
	sig("Drupal", `/sites/default/|drupal\.settings|content="drupal`),
	sig("Magento", `/skin/frontend/|mage/cookies|magento`),
	sig("Shopify", `myshopify\.com|/cdn/shop/|x-shopid`),
	sig("Ghost", `ghost/api/|content="ghost`),
	sig("PrestaShop", `prestashop`),
	sig("OpenCart", `catalog/view/theme|route=product`),

	// JS frameworks
	sig("jQuery", `jquery[.-]?(\d|min)`),
	sig("React", `react(\.min)?\.js|data-reactroot|_react`),
	sig("Next.js", `__next_data__|/_next/static`),
	sig("Vue.js", `vue(\.min)?\.js|data-v-[a-f0-9]{8}`),
	sig("Nuxt.js", `__nuxt__`),
	sig("Angular", `ng-version|angular(\.min)?\.js`),
	sig("Svelte", `svelte`),
	sig("Alpine.js", `alpinejs|x-data=`),
	sig("GSAP", `gsap|tweenmax|tweenlite`),
	sig("Three.js", `three(\.min)?\.js|THREE\.`),
	sig("D3.js", `d3(\.min)?\.js`),
	sig("HTMX", `htmx(\.min)?\.js|hx-get=|hx-post=`),

	// CSS / UI
	sig("Bootstrap", `bootstrap(\.min)?\.(css|js)`),
	sig("Tailwind CSS", `tailwind`),
	sig("Font Awesome", `font-?awesome`),
	sig("Bulma", `bulma(\.min)?\.css`),

	// Analytics / marketing
	sig("Google Analytics", `google-analytics\.com|googletagmanager|gtag\(`),
	sig("Facebook Pixel", `fbq\(|connect\.facebook\.net`),
	sig("Hotjar", `hotjar`),
	sig("Mixpanel", `mixpanel`),
	sig("Segment", `segment\.(com|io)`),
	sig("Amplitude", `amplitude`),
	sig("Matomo", `matomo|piwik`),

	// CDN / assets
	sig("CloudFront", `cloudfront\.net`),
	sig("Fastly", `fastly`),
	sig("jsDelivr", `cdn\.jsdelivr\.net`),
	sig("unpkg", `unpkg\.com`),
	sig("cdnjs", `cdnjs\.cloudflare\.com`),
	sig("Google Fonts", `fonts\.googleapis\.com`),

	// Infra / devops
	sig("Kubernetes", `x-kubernetes`),
	sig("GraphQL", `/graphql|application/graphql`),
	sig("Swagger/OpenAPI", `swagger-ui|openapi\.json`),
	sig("Prometheus", `prometheus`),
	sig("Grafana", `grafana`),
	sig("Jenkins", `x-jenkins`),
	sig("Vercel", `x-vercel-id`),
	sig("Netlify", `x-nf-request-id`),
	sig("AWS", `amazons3|x-amz-cf-id`),
	sig("Firebase", `firebaseapp\.com|firebase`),
}

// wafSignatures — wafw00f passive technique (header/cookie based).
var wafSignatures = []signature{
	sig("Cloudflare", `cloudflare|__cfduid|cf-ray|cf-cache-status`),
	sig("Akamai", `akamai|x-akamai`),
	sig("Incapsula/Imperva", `incapsula|x-iinfo|visid_incap|incap_ses`),
	sig("Sucuri", `sucuri|x-sucuri`),
	sig("AWS CloudFront/WAF", `x-amz-cf-id|x-amz-cf-pop|awselb`),
	sig("F5 BIG-IP ASM", `bigip|f5_`),
	sig("ModSecurity", `mod_security|noyb`),
	sig("Barracuda", `barra_counter_session|barracuda`),
	sig("Fortinet FortiWeb", `fortigate|fortiweb|fortiwafsid`),
	sig("StackPath", `stackpath`),
	sig("DDoS-Guard", `ddos-guard|__ddg`),
	sig("Reblaze", `reblaze|rbzid`),
	sig("Azure Front Door", `x-azure-ref|azurefd`),
	sig("Vercel", `x-vercel`),
	sig("Wordfence", `wordfence`),
	sig("QRATOR", `qrator|_qrator`),
	sig("NSFocus", `nsfocus|ns_af=`),
	sig("Yunjiasu (Baidu)", `yjs_js_security_pass`),
}

// serviceNames — common port → service mapping (nmap-services subset).
var serviceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
	443: "https", 445: "smb", 465: "smtps", 587: "smtp-sub", 993: "imaps",
	995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2082: "cpanel",
	2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl", 2095: "webmail",
	2096: "webmail-ssl", 2222: "directadmin", 2375: "docker", 2376: "docker-tls",
	3000: "dev-http", 3128: "squid", 3306: "mysql", 3389: "rdp", 3690: "svn",
	4444: "metasploit", 4848: "glassfish", 5000: "dev-http", 5432: "postgres",
	5555: "adb", 5631: "pcanywhere", 5800: "vnc-http", 5900: "vnc",
	5984: "couchdb", 5985: "winrm", 5986: "winrm-ssl", 6379: "redis",
	7001: "weblogic", 7002: "weblogic-ssl", 8000: "http-alt", 8008: "http-alt",
	8080: "http-proxy", 8081: "http-alt", 8086: "influxdb", 8088: "http-alt",
	8443: "https-alt", 8888: "http-alt", 9000: "portainer", 9001: "tor-or",
	9042: "cassandra", 9090: "prometheus", 9100: "node-exporter", 9200: "elasticsearch",
	9300: "es-transport", 9418: "git", 9999: "http-alt", 10000: "webmin",
	11211: "memcached", 27017: "mongodb", 27018: "mongodb", 50030: "hadoop",
	50060: "hadoop", 50070: "hadoop",
}

// bannerPorts are text protocols worth grabbing a banner from.
var bannerPorts = map[int]bool{
	21: true, 22: true, 23: true, 25: true, 110: true, 143: true,
	3306: true, 6379: true, 27017: true, 11211: true,
}
