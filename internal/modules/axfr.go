package modules

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Arseno25/nexprowl/internal/scanner"
)

// ─── AXFR zone transfer (dnsrecon technique) ──────────────
//
// Go's net package has no AXFR support, so this speaks the DNS wire
// protocol directly: TCP query per nameserver, parse answer records
// (with name compression), stop at the closing SOA or EOF.

const (
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeCNAME = 5
	dnsTypeSOA   = 6
	dnsTypePTR   = 12
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsTypeSRV   = 33
	dnsTypeCAA   = 257
	dnsTypeAXFR  = 252
)

var dnsTypeName = map[uint16]string{
	dnsTypeA: "A", dnsTypeNS: "NS", dnsTypeCNAME: "CNAME", dnsTypeSOA: "SOA",
	dnsTypePTR: "PTR", dnsTypeMX: "MX", dnsTypeTXT: "TXT", dnsTypeAAAA: "AAAA",
	dnsTypeSRV: "SRV", dnsTypeCAA: "CAA",
}

var (
	errShortPacket     = errors.New("short dns packet")
	errNamePointerLoop = errors.New("dns name compression pointer loop")
)

// tryZoneTransfer attempts AXFR against every authoritative NS.
// On success it records the zone and returns extracted hostnames.
func tryZoneTransfer(ctx context.Context, sc *scanner.ScanContext) []string {
	ns := nameservers(ctx, sc)
	if len(ns) == 0 {
		return nil
	}

	for _, server := range ns {
		records, hosts, err := axfr(ctx, sc, server, sc.Target)
		if err != nil || len(records) == 0 {
			continue
		}
		// Zone dumped — this is a high-impact misconfiguration.
		sc.Result.ZoneTransfer = append(sc.Result.ZoneTransfer, scanner.AXFREntry{
			Server:  server,
			Records: records,
		})
		sc.Found("axfr", "ZONE TRANSFER successful from %s — %d records!", server, len(records))
		return hosts // one successful server is enough
	}
	return nil
}

// nameservers returns authoritative NS hostnames (from the DNS module
// result when available, otherwise a fresh lookup).
func nameservers(ctx context.Context, sc *scanner.ScanContext) []string {
	if sc.Result.DNS != nil && len(sc.Result.DNS.NS) > 0 {
		out := make([]string, 0, len(sc.Result.DNS.NS))
		for _, n := range sc.Result.DNS.NS {
			out = append(out, strings.TrimSuffix(n, "."))
		}
		return out
	}
	c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
	defer cancel()
	nss, err := sc.Resolver().LookupNS(c, sc.Target)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(nss))
	for _, n := range nss {
		out = append(out, strings.TrimSuffix(n.Host, "."))
	}
	return out
}

// axfr performs one zone transfer attempt against a single nameserver.
func axfr(ctx context.Context, sc *scanner.ScanContext, ns, zone string) ([]string, []string, error) {
	// Resolve the NS hostname → IP so we dial the server directly.
	c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
	nsIPs, err := sc.Resolver().LookupIP(c, "ip4", ns)
	cancel()
	if err != nil || len(nsIPs) == 0 {
		return nil, nil, fmt.Errorf("cannot resolve ns %s", ns)
	}

	dialer := &net.Dialer{Timeout: sc.Opts.Timeout}
	c2, cancel2 := context.WithTimeout(ctx, 12*time.Second)
	defer cancel2()
	conn, err := dialer.DialContext(c2, "tcp", net.JoinHostPort(nsIPs[0].String(), "53"))
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	// Send AXFR query (TCP DNS = 2-byte length prefix + message).
	query := buildDNSQuery(zone, dnsTypeAXFR, 0x2525)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(query)))
	if _, err := conn.Write(append(lenBuf[:], query...)); err != nil {
		return nil, nil, err
	}

	var records, hosts []string
	soaCount := 0
	for {
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break // server closed = end of transfer
			}
			return records, hosts, err
		}
		msg := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			break
		}
		lines, names, err := parseDNSMessage(msg)
		if err != nil {
			continue
		}
		for _, l := range lines {
			records = append(records, l)
			if strings.HasPrefix(l, zone+" SOA ") || strings.Contains(l, " SOA ") {
				soaCount++
			}
		}
		hosts = append(hosts, names...)
		// AXFR: zone starts and ends with SOA — second SOA means done.
		if soaCount >= 2 {
			break
		}
	}
	return records, hosts, nil
}

// buildDNSQuery builds a minimal DNS query message for one question.
func buildDNSQuery(domain string, qtype, id uint16) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, id)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0000)) // standard query
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))      // QDCOUNT
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))      // ANCOUNT
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))      // NSCOUNT
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))      // ARCOUNT
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 {
			continue
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	_ = binary.Write(&buf, binary.BigEndian, qtype)
	_ = binary.Write(&buf, binary.BigEndian, uint16(1)) // IN
	return buf.Bytes()
}

// maxNamePointers caps compression-pointer jumps. A hostile nameserver can
// craft pointers that cycle (e.g. one pointing at itself), which would spin
// decodeName forever — the pointer target is not required to move forward.
const maxNamePointers = 64

// decodeName reads a (possibly compressed) domain name at offset.
// Returns the name and the offset just past the name at its first position.
func decodeName(msg []byte, offset int) (string, int, error) {
	var labels []string
	end := -1
	pointers := 0
	for {
		if offset >= len(msg) {
			return "", 0, errShortPacket
		}
		l := int(msg[offset])
		switch {
		case l == 0:
			if end == -1 {
				end = offset + 1
			}
			return strings.Join(labels, "."), end, nil
		case l&0xC0 == 0xC0: // compression pointer
			if offset+1 >= len(msg) {
				return "", 0, errShortPacket
			}
			ptr := (l&0x3F)<<8 | int(msg[offset+1])
			if end == -1 {
				end = offset + 2
			}
			pointers++
			if pointers > maxNamePointers {
				return "", 0, errNamePointerLoop
			}
			offset = ptr
		default:
			offset++
			if offset+l > len(msg) {
				return "", 0, errShortPacket
			}
			labels = append(labels, string(msg[offset:offset+l]))
			offset += l
		}
	}
}

// parseDNSMessage extracts answer records as text lines + hostnames.
func parseDNSMessage(msg []byte) ([]string, []string, error) {
	if len(msg) < 12 {
		return nil, nil, errShortPacket
	}
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	if anCount == 0 {
		return nil, nil, nil
	}

	// skip header + question section
	offset := 12
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	for i := 0; i < qdCount; i++ {
		_, next, err := decodeName(msg, offset)
		if err != nil {
			return nil, nil, err
		}
		offset = next + 4 // QTYPE + QCLASS
	}

	var lines, hosts []string
	for i := 0; i < anCount; i++ {
		name, next, err := decodeName(msg, offset)
		if err != nil {
			break
		}
		offset = next
		if offset+10 > len(msg) {
			break
		}
		rtype := binary.BigEndian.Uint16(msg[offset : offset+2])
		rdLen := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
		offset += 10
		if offset+rdLen > len(msg) {
			break
		}
		rdata := msg[offset : offset+rdLen]

		typeName := dnsTypeName[rtype]
		if typeName == "" {
			typeName = fmt.Sprintf("TYPE%d", rtype)
		}
		value := ""
		switch rtype {
		case dnsTypeA:
			if rdLen == 4 {
				value = net.IP(rdata).String()
				hosts = append(hosts, name)
			}
		case dnsTypeAAAA:
			if rdLen == 16 {
				value = net.IP(rdata).String()
				hosts = append(hosts, name)
			}
		case dnsTypeCNAME, dnsTypeNS, dnsTypePTR:
			if v, _, err := decodeName(msg, offset); err == nil {
				value = v
				hosts = append(hosts, name, v)
			}
		case dnsTypeMX:
			if rdLen >= 3 {
				if v, _, err := decodeName(msg, offset+2); err == nil {
					value = fmt.Sprintf("%d %s", binary.BigEndian.Uint16(rdata[:2]), v)
					hosts = append(hosts, v)
				}
			}
		case dnsTypeSRV:
			if rdLen >= 7 {
				if v, _, err := decodeName(msg, offset+6); err == nil {
					value = fmt.Sprintf("%d %d %d %s",
						binary.BigEndian.Uint16(rdata[:2]),
						binary.BigEndian.Uint16(rdata[2:4]),
						binary.BigEndian.Uint16(rdata[4:6]), v)
					hosts = append(hosts, v)
				}
			}
		case dnsTypeSOA:
			mname, next2, err1 := decodeName(msg, offset)
			rname, _, err2 := decodeName(msg, next2)
			if err1 == nil && err2 == nil {
				value = mname + " " + rname
			}
		case dnsTypeTXT:
			if rdLen >= 1 {
				n := int(rdata[0])
				if 1+n <= rdLen {
					value = string(rdata[1 : 1+n])
				}
			}
		case dnsTypeCAA:
			if rdLen >= 3 {
				tagLen := int(rdata[1])
				if 2+tagLen <= rdLen {
					value = fmt.Sprintf("%d %s %s", rdata[0],
						string(rdata[2:2+tagLen]), string(rdata[2+tagLen:]))
				}
			}
		}
		if value != "" {
			lines = append(lines, fmt.Sprintf("%s %s %s", name, typeName, value))
		}
		offset += rdLen
	}
	return lines, hosts, nil
}
