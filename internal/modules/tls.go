package modules

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"dscan/internal/scanner"
)

// TLS pulls certificate details: version, cipher, issuer, validity
// (with expired flag), and SANs (bonus subdomain intel).
type TLS struct{}

func (TLS) Name() string { return "tls" }

func (TLS) Run(ctx context.Context, sc *scanner.ScanContext) error {
	c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout+2*time.Second)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: sc.Opts.Timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, // we want expired/self-signed certs too
			ServerName:         sc.Target,
		},
	}
	rawConn, err := dialer.DialContext(c, "tcp", net.JoinHostPort(sc.Target, "443"))
	if err != nil {
		sc.Log(scanner.LevelInfo, "tls: %v", err)
		return nil // no TLS is not a module failure
	}
	conn, ok := rawConn.(*tls.Conn)
	if !ok {
		_ = rawConn.Close()
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	cert := state.PeerCertificates[0]

	tr := &scanner.TLSResult{
		Issuer:    cert.Issuer.String(),
		Subject:   cert.Subject.String(),
		ValidFrom: cert.NotBefore.Format("2006-01-02"),
		ValidTo:   cert.NotAfter.Format("2006-01-02"),
		Version:   tlsVersionName(state.Version),
		Cipher:    tls.CipherSuiteName(state.CipherSuite),
		Expired:   time.Now().After(cert.NotAfter),
	}
	tr.SANs = scanner.UniqueSorted(append(tr.SANs, cert.DNSNames...))
	sc.Result.TLS = tr

	sc.Log(scanner.LevelSuccess, "%s | %s", tr.Version, tr.Cipher)
	sc.Log(scanner.LevelSuccess, "issuer: %s", tr.Issuer)
	if tr.Expired {
		sc.Log(scanner.LevelError, "valid: %s → %s [EXPIRED]", tr.ValidFrom, tr.ValidTo)
	} else {
		sc.Log(scanner.LevelSuccess, "valid: %s → %s", tr.ValidFrom, tr.ValidTo)
	}
	if len(tr.SANs) > 0 {
		show := tr.SANs
		suffix := ""
		if len(show) > 8 {
			show, suffix = show[:8], " …"
		}
		sc.Log(scanner.LevelInfo, "SANs (%d): %v%s", len(tr.SANs), show, suffix)
	}
	return nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0 (insecure)"
	case tls.VersionTLS11:
		return "TLS 1.1 (insecure)"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
