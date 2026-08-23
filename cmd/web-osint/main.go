package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Report struct {
	Target      string         `json:"target"`
	GeneratedAt time.Time      `json:"generated_at"`
	HTTP        HTTPInfo       `json:"http"`
	DNS         DNSInfo        `json:"dns"`
	TLS         *TLSInfo       `json:"tls,omitempty"`
	RDAP        *RDAPInfo      `json:"rdap,omitempty"`
	Network     *NetworkInfo   `json:"network,omitempty"`
	Technologies []string       `json:"technologies,omitempty"`
	Trackers    []string       `json:"trackers,omitempty"`
	Security    map[string]string `json:"security"`
	Subdomains  []string       `json:"subdomains,omitempty"`
	Resources   Resources      `json:"resources"`
	Errors      []string       `json:"errors,omitempty"`
}

type HTTPInfo struct {
	Status       string            `json:"status"`
	StatusCode   int               `json:"status_code"`
	FinalURL     string            `json:"final_url"`
	Server       string            `json:"server,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
	ResponseTime int64             `json:"response_time_ms"`
	Headers      map[string]string `json:"selected_headers,omitempty"`
}

type DNSInfo struct {
	A    []string `json:"A,omitempty"`
	AAAA []string `json:"AAAA,omitempty"`
	MX   []string `json:"MX,omitempty"`
	NS   []string `json:"NS,omitempty"`
	TXT  []string `json:"TXT,omitempty"`
}

type TLSInfo struct {
	Version    string    `json:"version"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	Expires    time.Time `json:"expires"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	Valid      bool      `json:"valid"`
	Verified   bool      `json:"verified"`
	SelfSigned bool      `json:"self_signed"`
}

type RDAPInfo struct {
	Handle      string   `json:"handle"`
	Status      []string `json:"status,omitempty"`
	Registrar   string   `json:"registrar,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	Events      []string `json:"events,omitempty"`
}

type NetworkInfo struct {
	IP           string `json:"ip"`
	Country      string `json:"country,omitempty"`
	City         string `json:"city,omitempty"`
	ASN          string `json:"asn,omitempty"`
	Organization string `json:"organization,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
}

type Resources struct {
	Robots  bool `json:"robots_txt"`
	Sitemap bool `json:"sitemap_xml"`
}

type rdapResponse struct {
	Handle string `json:"handle"`
	Status []string `json:"status"`
	Entities []struct {
		Roles      []string `json:"roles"`
		VCardArray []any    `json:"vcardArray"`
	} `json:"entities"`
	Nameservers []struct { LdhName string `json:"ldhName"` } `json:"nameservers"`
	Events []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
}

const (
	userAgent    = "web-osint/0.3 (+https://github.com/linuxaaron/web-osint)"
	maxHTMLBytes = 4 << 20
)

var httpClient = &http.Client{
	Timeout: 12 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 8 {
			return errors.New("too many redirects")
		}
		if err := validatePublicHostname(req.URL.Hostname()); err != nil {
			return fmt.Errorf("unsafe redirect target: %w", err)
		}
		return nil
	},
}

func main() {
	jsonOut := flag.Bool("json", false, "write JSON report")
	full := flag.Bool("full", false, "run extended public OSINT checks")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Println("usage: web-osint [--json] [--full] <domain-or-url>")
		return
	}

	r := analyze(flag.Arg(0), *full)
	if *jsonOut {
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		return
	}
	printReport(r)
}

func analyze(target string, full bool) Report {
	r := Report{Target: strings.TrimSpace(target), GeneratedAt: time.Now(), Security: map[string]string{}}
	raw, host, err := normalizeTarget(target)
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
		return r
	}
	r.Target = host

	r.HTTP = inspectHTTP(raw)
	if r.HTTP.Status == "" {
		r.Errors = append(r.Errors, "HTTP inspection failed")
	}
	r.DNS = inspectDNS(host)
	if strings.HasPrefix(r.HTTP.FinalURL, "https://") || strings.HasPrefix(raw, "https://") {
		r.TLS = inspectTLS(host)
	}
	r.Technologies, r.Trackers = inspectHTML(r.HTTP.FinalURL)
	r.Security = securityHeaders(r.HTTP.Headers)

	if full {
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); r.RDAP = inspectRDAP(host) }()
		go func() { defer wg.Done(); r.Network = inspectNetwork(r.DNS.A) }()
		go func() { defer wg.Done(); r.Subdomains = inspectCT(host) }()
		go func() { defer wg.Done(); r.Resources = inspectResources(host) }()
		wg.Wait()
	}
	return r
}

func normalizeTarget(target string) (string, string, error) {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return "", "", errors.New("invalid target: empty value")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", "", errors.New("invalid target")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", errors.New("invalid target: only http and https are supported")
	}
	if u.User != nil {
		return "", "", errors.New("invalid target: userinfo is not allowed")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if err := validatePublicHostname(host); err != nil {
		return "", "", err
	}
	u.Host = host
	return u.String(), host, nil
}

func validatePublicHostname(host string) error {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return errors.New("invalid target: empty hostname")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return errors.New("invalid target: private, loopback, link-local or special-use IP is not allowed")
		}
		return nil
	}
	if strings.Contains(host, "/") || strings.Contains(host, "\\") || strings.Contains(host, "@") {
		return errors.New("invalid target hostname")
	}
	if len(host) > 253 || !strings.Contains(host, ".") {
		return errors.New("invalid target: expected a public domain name or IP address")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid target: malformed hostname")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return errors.New("invalid target: malformed hostname")
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("invalid target: hostname does not resolve: %s", host)
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return errors.New("invalid target: hostname resolves to a private or special-use address")
		}
	}
	return nil
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return true
}

func newRequest(method, raw string) (*http.Request, error) {
	req, err := http.NewRequest(method, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}

func inspectHTTP(raw string) HTTPInfo {
	req, err := newRequest(http.MethodGet, raw)
	if err != nil {
		return HTTPInfo{Status: err.Error()}
	}
	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil && strings.HasPrefix(raw, "https://") {
		fallback := "http://" + strings.TrimPrefix(raw, "https://")
		req, reqErr := newRequest(http.MethodGet, fallback)
		if reqErr == nil {
			start = time.Now()
			resp, err = httpClient.Do(req)
		}
	}
	if err != nil {
		return HTTPInfo{Status: err.Error(), ResponseTime: time.Since(start).Milliseconds()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2<<20))
	headers := map[string]string{}
	for _, k := range []string{"Server", "Content-Type", "Location", "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"} {
		if v := resp.Header.Get(k); v != "" {
			headers[k] = v
		}
	}
	return HTTPInfo{
		Status: resp.Status, StatusCode: resp.StatusCode, FinalURL: resp.Request.URL.String(),
		Server: resp.Header.Get("Server"), ContentType: resp.Header.Get("Content-Type"),
		ResponseTime: time.Since(start).Milliseconds(), Headers: headers,
	}
}

func inspectHTML(raw string) ([]string, []string) {
	if raw == "" {
		return nil, nil
	}
	req, err := newRequest(http.MethodGet, raw)
	if err != nil {
		return nil, nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxHTMLBytes))
	if err != nil {
		return nil, nil
	}
	s := strings.ToLower(string(b))
	sig := map[string][]string{
		"WordPress": {"wp-content", "wp-includes", "wordpress"},
		"Next.js": {"__next_data__", "/_next/"},
		"React": {"data-reactroot", "react.production.min.js", "react-dom"},
		"Vue.js": {"vue.js", "__vue__", "data-v-"},
		"Angular": {"ng-version", "angular.min.js"},
		"Bootstrap": {"bootstrap.min.css", "bootstrap.min.js"},
		"jQuery": {"jquery.min.js", "jquery.js"},
		"Google Tag Manager": {"googletagmanager.com/gtm.js", "gtag/js"},
		"Cloudflare": {"cf-ray", "__cf_bm"},
	}
	found := map[string]bool{}
	for name, patterns := range sig {
		for _, pattern := range patterns {
			if strings.Contains(s, pattern) {
				found[name] = true
				break
			}
		}
	}
	tech := make([]string, 0, len(found))
	for name := range found { tech = append(tech, name) }
	sort.Strings(tech)

	trackerPatterns := map[string][]string{
		"Google Analytics": {"google-analytics.com", "googletagmanager.com"},
		"Meta Pixel": {"connect.facebook.net", "fbq("},
		"Matomo": {"matomo.js", "piwik.js"},
		"Hotjar": {"hotjar.com"},
		"Microsoft Clarity": {"clarity.ms"},
	}
	trackers := []string{}
	for name, patterns := range trackerPatterns {
		for _, pattern := range patterns {
			if strings.Contains(s, pattern) {
				trackers = append(trackers, name)
				break
			}
		}
	}
	sort.Strings(trackers)
	return tech, trackers
}

func inspectDNS(host string) DNSInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	d := DNSInfo{}
	if ips, _ := net.DefaultResolver.LookupIP(ctx, "ip", host); len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() != nil { d.A = uniq(d.A, ip.String()) } else { d.AAAA = uniq(d.AAAA, ip.String()) }
		}
	}
	if mx, _ := net.DefaultResolver.LookupMX(ctx, host); len(mx) > 0 {
		for _, v := range mx { d.MX = uniq(d.MX, strings.TrimSuffix(v.Host, ".")) }
	}
	if ns, _ := net.DefaultResolver.LookupNS(ctx, host); len(ns) > 0 {
		for _, v := range ns { d.NS = uniq(d.NS, strings.TrimSuffix(v.Host, ".")) }
	}
	if txt, _ := net.DefaultResolver.LookupTXT(ctx, host); len(txt) > 0 { d.TXT = txt }
	return d
}

func inspectTLS(host string) *TLSInfo {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second}, "tcp", net.JoinHostPort(host, "443"), &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil { return nil }
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 { return nil }
	cert := state.PeerCertificates[0]
	validTime := cert.NotBefore.Before(time.Now()) && cert.NotAfter.After(time.Now())
	verified := false
	if roots, poolErr := x509.SystemCertPool(); poolErr == nil && roots != nil {
		_, verifyErr := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, Intermediates: certPool(state.PeerCertificates[1:])})
		verified = verifyErr == nil
	}
	selfSigned := cert.CheckSignatureFrom(cert) == nil
	return &TLSInfo{
		Version: tlsVersion(state.Version), Subject: cert.Subject.String(), Issuer: cert.Issuer.String(),
		Expires: cert.NotAfter, DNSNames: cert.DNSNames, Valid: validTime && verified,
		Verified: verified, SelfSigned: selfSigned,
	}
}

func certPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs { pool.AddCert(cert) }
	return pool
}

func inspectRDAP(host string) *RDAPInfo {
	req, err := newRequest(http.MethodGet, "https://rdap.org/domain/"+url.PathEscape(host))
	if err != nil { return nil }
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode >= 400 { if resp != nil { resp.Body.Close() }; return nil }
	defer resp.Body.Close()
	var d rdapResponse
	if json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&d) != nil { return nil }
	r := &RDAPInfo{Handle: d.Handle, Status: d.Status}
	for _, n := range d.Nameservers { if n.LdhName != "" { r.Nameservers = append(r.Nameservers, n.LdhName) } }
	for _, e := range d.Events { if e.EventAction != "" { r.Events = append(r.Events, e.EventAction+": "+e.EventDate) } }
	for _, entity := range d.Entities {
		for _, role := range entity.Roles {
			if role == "registrar" { r.Registrar = vcardName(entity.VCardArray) }
		}
	}
	return r
}

func vcardName(v []any) string {
	b, _ := json.Marshal(v)
	m := regexp.MustCompile(`(?i)"fn"\s*,\s*\[?"?([^"\],]+)`).FindStringSubmatch(string(b))
	if len(m) > 1 { return strings.TrimSpace(m[1]) }
	return ""
}

func inspectNetwork(ips []string) *NetworkInfo {
	if len(ips) == 0 { return nil }
	ip := net.ParseIP(ips[0])
	if ip == nil || !isPublicIP(ip) { return nil }
	req, err := newRequest(http.MethodGet, "https://ipwho.is/"+url.PathEscape(ips[0]))
	if err != nil { return nil }
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode >= 400 { if resp != nil { resp.Body.Close() }; return nil }
	defer resp.Body.Close()
	var d struct {
		Success bool `json:"success"`
		IP, Country, City, Hostname string
		Connection struct { ASN int `json:"asn"`; Org string `json:"org"` } `json:"connection"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d) != nil || !d.Success { return nil }
	return &NetworkInfo{IP: d.IP, Country: d.Country, City: d.City, ASN: fmt.Sprintf("AS%d", d.Connection.ASN), Organization: d.Connection.Org, Hostname: d.Hostname}
}

func inspectCT(host string) []string {
	req, err := newRequest(http.MethodGet, "https://crt.sh/?q=%25."+url.QueryEscape(host)+"&output=json")
	if err != nil { return nil }
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode >= 400 { if resp != nil { resp.Body.Close() }; return nil }
	defer resp.Body.Close()
	var rows []struct { NameValue string `json:"name_value"` }
	if json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&rows) != nil { return nil }
	out := []string{}
	for _, row := range rows {
		for _, name := range strings.Split(row.NameValue, "\n") {
			name = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*.")
			if name == host || strings.HasSuffix(name, "."+host) { out = uniq(out, name) }
		}
	}
	sort.Strings(out)
	return out
}

func inspectResources(host string) Resources {
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 { return http.ErrUseLastResponse }
		return validatePublicHostname(req.URL.Hostname())
	}}
	return Resources{Robots: exists(client, "https://"+host+"/robots.txt"), Sitemap: exists(client, "https://"+host+"/sitemap.xml")}
}

func exists(client *http.Client, raw string) bool {
	req, err := newRequest(http.MethodHead, raw)
	if err != nil { return false }
	resp, err := client.Do(req)
	if err != nil { return false }
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func securityHeaders(headers map[string]string) map[string]string {
	out := map[string]string{}
	for _, key := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"} {
		if value := headers[key]; value != "" { out[key] = value } else { out[key] = "missing" }
	}
	return out
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13: return "TLS 1.3"
	case tls.VersionTLS12: return "TLS 1.2"
	default: return fmt.Sprintf("0x%x", version)
	}
}

func uniq(values []string, value string) []string {
	for _, existing := range values { if existing == value { return values } }
	return append(values, value)
}

func join(values []string) string {
	if len(values) == 0 { return "-" }
	return strings.Join(values, ", ")
}

func val(value string) string {
	if value == "" { return "-" }
	return value
}

func printReport(r Report) {
	fmt.Printf("web-osint 0.3 — public web intelligence\n\nTarget: %s\n\nHTTP\n  Status:       %s\n  Final URL:    %s\n  Server:       %s\n  Response:     %d ms\n\nDNS\n  A:            %s\n  AAAA:         %s\n  MX:           %s\n  NS:           %s\n", r.Target, r.HTTP.Status, val(r.HTTP.FinalURL), val(r.HTTP.Server), r.HTTP.ResponseTime, join(r.DNS.A), join(r.DNS.AAAA), join(r.DNS.MX), join(r.DNS.NS))
	if r.TLS != nil {
		fmt.Printf("\nTLS\n  Version:       %s\n  Issuer:        %s\n  Expires:       %s\n  Valid:         %t\n  Verified:      %t\n  Self-signed:   %t\n", r.TLS.Version, r.TLS.Issuer, r.TLS.Expires.Format(time.RFC3339), r.TLS.Valid, r.TLS.Verified, r.TLS.SelfSigned)
	}
	if r.RDAP != nil {
		fmt.Printf("\nRDAP\n  Handle:        %s\n  Registrar:     %s\n  Status:        %s\n  Nameservers:   %s\n", val(r.RDAP.Handle), val(r.RDAP.Registrar), join(r.RDAP.Status), join(r.RDAP.Nameservers))
	}
	if r.Network != nil {
		fmt.Printf("\nNETWORK\n  IP:            %s\n  ASN:           %s\n  Organization:  %s\n  Country:       %s\n  City:          %s\n", r.Network.IP, val(r.Network.ASN), val(r.Network.Organization), val(r.Network.Country), val(r.Network.City))
	}
	fmt.Printf("\nTechnologies: %s\nTrackers:     %s\n\nSecurity headers\n", join(r.Technologies), join(r.Trackers))
	keys := make([]string, 0, len(r.Security))
	for key := range r.Security { keys = append(keys, key) }
	sort.Strings(keys)
	for _, key := range keys { fmt.Printf("  %-28s %s\n", key+":", r.Security[key]) }
	if len(r.Subdomains) > 0 { fmt.Printf("\nCertificate Transparency subdomains (%d)\n  %s\n", len(r.Subdomains), join(r.Subdomains)) }
	fmt.Printf("\nResources\n  robots.txt:   %t\n  sitemap.xml:  %t\n", r.Resources.Robots, r.Resources.Sitemap)
	if len(r.Errors) > 0 { fmt.Printf("\nErrors\n  %s\n", strings.Join(r.Errors, "\n  ")) }
	fmt.Println("\nTraffic: authoritative visitor counts are not inferred. Public estimates are only added when backed by a documented measurement source.")
}
