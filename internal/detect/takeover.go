package detect

import "strings"

// TakeoverFingerprint describes one claimable hosting service.
//
// Suffix is matched against the CNAME on a label boundary. Body is a
// marker string the service returns when the name is pointed at it but
// nothing is registered — the only evidence available for providers that
// keep resolving a dangling name (GitHub Pages, Shopify, Heroku, …), which
// is the majority of real-world takeovers. Empty Body means the service can
// only be confirmed via NXDOMAIN.
type TakeoverFingerprint struct {
	Suffix  string
	Service string
	Body    string
}

// takeoverFingerprints — subjack/nuclei/can-i-take-over-xyz technique.
// Body markers are lowercase; matching is case-insensitive.
var takeoverFingerprints = []TakeoverFingerprint{
	{"amazonaws.com", "AWS S3/CloudFront/ELB", "nosuchbucket"},
	{"cloudfront.net", "AWS CloudFront", ""},
	{"elasticbeanstalk.com", "AWS Elastic Beanstalk", ""},
	{"herokuapp.com", "Heroku", "no such app"},
	{"herokudns.com", "Heroku", "no such app"},
	{"github.io", "GitHub Pages", "there isn't a github pages site here"},
	{"azurewebsites.net", "Azure Web Apps", ""},
	{"cloudapp.net", "Azure CloudApp", ""},
	{"azure-api.net", "Azure API Management", ""},
	{"trafficmanager.net", "Azure Traffic Manager", ""},
	{"blob.core.windows.net", "Azure Blob", ""},
	{"pantheon.io", "Pantheon", "the gods are wise, but do not know of the site which you seek"},
	{"pantheonsite.io", "Pantheon", "the gods are wise, but do not know of the site which you seek"},
	{"wpengine.com", "WP Engine", ""},
	{"zendesk.com", "Zendesk", "help center closed"},
	{"fastly.net", "Fastly", "fastly error: unknown domain"},
	{"surge.sh", "Surge.sh", "project not found"},
	{"bitbucket.io", "Bitbucket", "repository not found"},
	{"unbouncepages.com", "Unbounce", "the requested url was not found on this server"},
	{"tumblr.com", "Tumblr", "whatever you were looking for doesn't currently exist at this address"},
	{"wordpress.com", "WordPress.com", "do you want to register"},
	{"fly.dev", "Fly.io", ""},
	{"vercel.app", "Vercel", "the deployment could not be found"},
	{"netlify.app", "Netlify", "not found - request id"},
	{"onrender.com", "Render", ""},
	{"railway.app", "Railway", ""},
	{"cargocollective.com", "Cargo", ""},
	{"ghost.io", "Ghost", "the thing you were looking for is no longer here"},
	{"helpjuice.com", "Helpjuice", "we could not find what you're looking for"},
	{"helpscoutdocs.com", "HelpScout", "no settings were found for this company"},
	{"intercom.help", "Intercom", "uh oh. that page doesn't exist"},
	{"freshdesk.com", "Freshdesk", ""},
	{"myshopify.com", "Shopify", "sorry, this shop is currently unavailable"},
	{"bigcartel.com", "Big Cartel", "oops! we couldn"},
	{"squarespace.com", "Squarespace", ""},
	{"webflow.io", "Webflow", "the page you are looking for doesn't exist or has been moved"},
	{"wixsite.com", "Wix", ""},
	{"strikingly.com", "Strikingly", "but if you're looking to build your own website"},
	{"weebly.com", "Weebly", ""},
	{"tilda.ws", "Tilda", "please renew your subscription"},
	{"landingi.com", "Landingi", "it looks like you're lost"},
	{"teamwork.com", "Teamwork", "oops - we didn't find your site"},
	{"readme.io", "ReadMe", "project doesnt exist"},
	{"statuspage.io", "Statuspage", ""},
	{"edgekey.net", "Akamai", ""},
	{"edgesuite.net", "Akamai", ""},
	{"firebaseapp.com", "Firebase", "site not found"},
	{"web.app", "Firebase", "site not found"},
}

// MatchTakeover returns the fingerprint whose Suffix owns the CNAME, or nil.
// The suffix must align with a label boundary, so "evil-amazonaws.com.attacker.net"
// does not match "amazonaws.com".
func MatchTakeover(cname string) *TakeoverFingerprint {
	c := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cname)), ".")
	for i := range takeoverFingerprints {
		s := takeoverFingerprints[i].Suffix
		if c == s || strings.HasSuffix(c, "."+s) {
			return &takeoverFingerprints[i]
		}
	}
	return nil
}

// MatchesBody reports whether a response body carries this service's
// "nothing is registered here" marker.
func (f *TakeoverFingerprint) MatchesBody(body string) bool {
	if f.Body == "" {
		return false
	}
	return strings.Contains(strings.ToLower(body), f.Body)
}
