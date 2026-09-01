package main

import (
	"net"
	"testing"
)

func TestValidatePublicHostnameRejectsPrivateAndMalformedTargets(t *testing.T) {
	tests := []string{
		"",
		"localhost",
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.10",
		"169.254.1.1",
		"bad_host.example.com",
		"-bad.example.com",
	}
	for _, target := range tests {
		if err := validatePublicHostname(target); err == nil {
			t.Errorf("validatePublicHostname(%q) unexpectedly succeeded", target)
		}
	}
}

func TestNormalizeTargetRejectsUnsafeSchemesAndUserinfo(t *testing.T) {
	for _, target := range []string{
		"ftp://example.com",
		"file:///etc/passwd",
		"https://user:password@example.com",
		"http://127.0.0.1",
	} {
		if _, _, err := normalizeTarget(target); err == nil {
			t.Errorf("normalizeTarget(%q) unexpectedly succeeded", target)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	public := net.ParseIP("1.1.1.1")
	private := net.ParseIP("10.0.0.1")
	loopback := net.ParseIP("127.0.0.1")

	if !isPublicIP(public) {
		t.Fatal("expected public IP to be accepted")
	}
	if isPublicIP(private) {
		t.Fatal("expected private IP to be rejected")
	}
	if isPublicIP(loopback) {
		t.Fatal("expected loopback IP to be rejected")
	}
}

func TestSecurityHeadersMarksMissingValues(t *testing.T) {
	result := securityHeaders(map[string]string{
		"Content-Security-Policy": "default-src 'self'",
	})
	if result["Content-Security-Policy"] != "default-src 'self'" {
		t.Fatal("existing security header was not preserved")
	}
	if result["X-Frame-Options"] != "missing" {
		t.Fatal("missing security header was not reported")
	}
}
