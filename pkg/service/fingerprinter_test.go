package service

import (
	"os"
	"strings"
	"testing"
)

func TestFingerprintFixtures(t *testing.T) {
	f, err := NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ file, name, product, version string }{
		{"ssh.txt", "ssh", "OpenSSH", "9.7p1"},
		{"http.txt", "http", "nginx", "1.26.0"},
	} {
		data, err := os.ReadFile("../../testdata/banners/" + tc.file)
		if err != nil {
			t.Fatal(err)
		}
		service := f.Match(data)
		if service == nil || service.Name != tc.name || service.Product != tc.product || service.Version != tc.version || len(service.Evidence) == 0 {
			t.Fatalf("%s: %+v", tc.file, service)
		}
	}
	for _, input := range []string{"", "220 SMTP ready\r\n", "SSH-2.0-incomplete", "HTTP/1.1 200 OK\r\nServer: incomplete", "HTTP/9.0 200 OK\r\n\r\n", "HTTP/1.1 999 BAD\r\n\r\n", "prefix HTTP/1.1 200 OK\r\n\r\n"} {
		if result := f.Match([]byte(input)); result != nil {
			t.Fatalf("false positive for %q: %+v", input, result)
		}
	}
	if result := f.Match([]byte("Notice\r\nSSH-2.0-dropbear_2024.85\r\n")); result == nil || result.Product != "dropbear" {
		t.Fatalf("SSH preamble unsupported: %+v", result)
	}
}

func FuzzFingerprint(f *testing.F) {
	engine, err := NewFingerprinter()
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{"SSH-2.0-OpenSSH_9.7\r\n", "HTTP/1.1 200 OK\r\nServer: test/1\r\n\r\n", "HTTP/1.1 200 OK\r\nServer: bad", "\xff\x00", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		result := engine.Match([]byte(input))
		if result != nil {
			if result.Name != "http" && result.Name != "ssh" || len(result.Product) > 128 || len(result.Version) > 128 {
				t.Fatalf("invalid service: %+v", result)
			}
			if strings.ContainsAny(result.Name, "\r\n") {
				t.Fatal("invalid protocol name")
			}
		}
	})
}
