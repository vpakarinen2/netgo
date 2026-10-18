// Package service implements bounded, best-effort protocol identification.
package service

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/vpakarinen2/netgo/pkg/model"
)

const MaxBytes = 65536

//go:embed signatures/*.yaml
var definitions embed.FS

type rule struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
}

type compiledRule struct {
	name    string
	pattern *regexp.Regexp
}

// Fingerprinter is immutable and safe for concurrent use. Only embedded rules
// are loaded; arbitrary user-supplied regex/rule files are not supported yet.
type Fingerprinter struct{ rules []compiledRule }

func NewFingerprinter() (*Fingerprinter, error) {
	files, err := definitions.ReadDir("signatures")
	if err != nil {
		return nil, err
	}
	f := &Fingerprinter{}
	seen := map[string]bool{}
	for _, file := range files {
		data, err := definitions.ReadFile("signatures/" + file.Name())
		if err != nil {
			return nil, err
		}
		var definition rule
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&definition); err != nil {
			return nil, err
		}
		if (definition.Name != "http" && definition.Name != "ssh") || seen[definition.Name] {
			return nil, fmt.Errorf("invalid or duplicate signature %q", definition.Name)
		}
		pattern, err := regexp.Compile(definition.Pattern)
		if err != nil {
			return nil, fmt.Errorf("signature %s: %w", definition.Name, err)
		}
		if definition.Name == "ssh" && pattern.NumSubexp() != 1 {
			return nil, fmt.Errorf("SSH signature needs one software capture")
		}
		f.rules = append(f.rules, compiledRule{definition.Name, pattern})
		seen[definition.Name] = true
	}
	return f, nil
}

// Match requires protocol evidence, never a port-number guess. Headers and
// banners are untrusted claims rather than authenticated software versions.
func (f *Fingerprinter) Match(data []byte) *model.Service {
	if len(data) > MaxBytes {
		data = data[:MaxBytes]
	}
	for _, rule := range f.rules {
		matches := rule.pattern.FindSubmatch(data)
		if matches == nil {
			continue
		}
		service := &model.Service{Name: rule.name}
		switch rule.name {
		case "ssh":
			service.Product, service.Version, _ = strings.Cut(string(matches[1]), "_")
			service.Evidence = []model.Evidence{evidence("banner", data)}
		case "http":
			if !bytes.Contains(data, []byte("\r\n\r\n")) && !bytes.Contains(data, []byte("\n\n")) {
				continue
			}
			response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), &http.Request{Method: http.MethodHead})
			if err != nil {
				continue
			}
			_ = response.Body.Close()
			service.Web = observeWeb(response)
			service.Evidence = []model.Evidence{{Kind: "http_status", Value: response.Proto + " " + response.Status}}
			server := response.Header.Get("Server")
			if server != "" {
				service.Evidence = append(service.Evidence, model.Evidence{Kind: "http_server", Value: server})
				software := strings.Fields(server)
				if len(software) != 0 {
					service.Product, service.Version, _ = strings.Cut(software[0], "/")
				}
			}
		}
		service.Product, service.Version = clipped(service.Product, 128), clipped(service.Version, 128)
		return service
	}
	return nil
}

func evidence(kind string, data []byte) model.Evidence {
	if !utf8.Valid(data) {
		return model.Evidence{Kind: kind + "_base64", Value: base64.StdEncoding.EncodeToString(data)}
	}
	return model.Evidence{Kind: kind, Value: string(data)}
}
