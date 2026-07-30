package detect

import "strings"

// TakeoverFingerprint maps a CNAME suffix to a claimable service.
type TakeoverFingerprint struct {
	Suffix  string
	Service string
}

// takeoverFingerprints — subjack/nuclei technique. If a subdomain's CNAME
// matches one of these AND the CNAME target does not resolve, the
// subdomain is dangling and potentially claimable by an attacker.
var takeoverFingerprints = []TakeoverFingerprint{
	{"amazonaws.com", "AWS S3/CloudFront/ELB"},
	{"s3-website", "AWS S3 Static Site"},
	{"cloudfront.net", "AWS CloudFront"},
	{"elasticbeanstalk.com", "AWS Elastic Beanstalk"},
	{"herokuapp.com", "Heroku"},
	{"herokudns.com", "Heroku"},
	{"github.io", "GitHub Pages"},
	{"azurewebsites.net", "Azure Web Apps"},
	{"cloudapp.net", "Azure CloudApp"},
	{"azure-api.net", "Azure API Management"},
	{"trafficmanager.net", "Azure Traffic Manager"},
	{"blob.core.windows.net", "Azure Blob"},
	{"pantheon.io", "Pantheon"},
	{"pantheonsite.io", "Pantheon"},
	{"wpengine.com", "WP Engine"},
	{"zendesk.com", "Zendesk"},
	{"fastly.net", "Fastly"},
	{"surge.sh", "Surge.sh"},
	{"bitbucket.io", "Bitbucket"},
	{"unbouncepages.com", "Unbounce"},
	{"tumblr.com", "Tumblr"},
	{"wordpress.com", "WordPress.com"},
	{"fly.dev", "Fly.io"},
	{"vercel.app", "Vercel"},
	{"netlify.app", "Netlify"},
	{"onrender.com", "Render"},
	{"railway.app", "Railway"},
	{"up.railway.app", "Railway"},
	{"cargocollective.com", "Cargo"},
	{"ghost.io", "Ghost"},
	{"helpjuice.com", "Helpjuice"},
	{"helpscoutdocs.com", "HelpScout"},
	{"intercom.help", "Intercom"},
	{"freshdesk.com", "Freshdesk"},
	{"myshopify.com", "Shopify"},
	{"bigcartel.com", "Big Cartel"},
	{"squarespace.com", "Squarespace"},
	{"webflow.io", "Webflow"},
	{"wixsite.com", "Wix"},
	{"strikingly.com", "Strikingly"},
	{"weebly.com", "Weebly"},
	{"tilda.ws", "Tilda"},
	{"landingi.com", "Landingi"},
	{"teamwork.com", "Teamwork"},
	{"readme.io", "ReadMe"},
	{"statuspage.io", "Statuspage"},
	{"edgekey.net", "Akamai"},
	{"edgesuite.net", "Akamai"},
	{"firebaseapp.com", "Firebase"},
	{"web.app", "Firebase"},
}

// MatchTakeover returns the claimable service for a CNAME, or "".
func MatchTakeover(cname string) string {
	c := strings.ToLower(cname)
	for _, fp := range takeoverFingerprints {
		if strings.Contains(c, fp.Suffix) {
			return fp.Service
		}
	}
	return ""
}
