// Package plugins loads and executes explicitly selected evidence-only Wasm checks.
package plugins

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/plugins/sdk"
)

const MaxPlugins = 16
const MaxModule = 8 * 1024 * 1024

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
var version = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$`)

type Manifest struct {
	APIVersion  string               `yaml:"api_version" json:"api_version"`
	ID          string               `yaml:"id" json:"id"`
	Version     string               `yaml:"version" json:"version"`
	Description string               `yaml:"description" json:"description"`
	Author      string               `yaml:"author" json:"author"`
	License     string               `yaml:"license" json:"license"`
	Module      string               `yaml:"module" json:"module"`
	SHA256      string               `yaml:"sha256" json:"sha256"`
	Permissions []string             `yaml:"permissions" json:"permissions"`
	Match       Match                `yaml:"match" json:"match"`
	Parameters  map[string]Parameter `yaml:"parameters" json:"parameters"`
}

type Match struct {
	Transport string   `yaml:"transport" json:"transport"`
	States    []string `yaml:"states" json:"states"`
	Services  []string `yaml:"services" json:"services,omitempty"`
}

type Parameter struct {
	Type      string `yaml:"type" json:"type"`
	Default   any    `yaml:"default" json:"default"`
	Minimum   *int64 `yaml:"minimum" json:"minimum,omitempty"`
	Maximum   *int64 `yaml:"maximum" json:"maximum,omitempty"`
	MaxLength *int   `yaml:"max_length" json:"max_length,omitempty"`
}

func ReadBounded(path string, limit int64) ([]byte, error) {
	before, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > limit {
		return nil, fmt.Errorf("file must be regular and at most %d bytes", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > limit {
		return nil, fmt.Errorf("file must be regular and at most %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}

func loadManifest(path string) (Manifest, []byte, error) {
	var manifest Manifest
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return manifest, nil, err
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return manifest, nil, err
	}
	data, err := ReadBounded(canonical, 64*1024)
	if err != nil {
		return manifest, nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return manifest, nil, err
	}
	if err := validateYAML(&root, 0); err != nil {
		return manifest, nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return manifest, nil, fmt.Errorf("expected one YAML document")
	}
	if err := manifest.validate(); err != nil {
		return manifest, nil, err
	}
	if filepath.IsAbs(manifest.Module) || filepath.VolumeName(manifest.Module) != "" {
		return manifest, nil, fmt.Errorf("module must be relative to the bundle")
	}
	rootDir := filepath.Dir(canonical)
	modulePath, err := filepath.EvalSymlinks(filepath.Join(rootDir, manifest.Module))
	if err != nil {
		return manifest, nil, err
	}
	rel, err := filepath.Rel(rootDir, modulePath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return manifest, nil, fmt.Errorf("module escapes the bundle")
	}
	module, err := ReadBounded(modulePath, MaxModule)
	if err != nil {
		return manifest, nil, err
	}
	digest := sha256.Sum256(module)
	if hex.EncodeToString(digest[:]) != manifest.SHA256 {
		return manifest, nil, fmt.Errorf("module SHA-256 mismatch")
	}
	return manifest, module, nil
}

func validateYAML(node *yaml.Node, depth int) error {
	if depth > 16 || node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("manifest aliases, anchors, or excessive nesting are unsupported")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			name := strings.ToLower(key.Value)
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[name] {
				return fmt.Errorf("invalid or duplicate manifest key %q", name)
			}
			seen[name] = true
		}
	}
	for _, child := range node.Content {
		if err := validateYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (m Manifest) validate() error {
	if m.APIVersion != sdk.APIVersion || !identifier.MatchString(m.ID) || !version.MatchString(m.Version) {
		return fmt.Errorf("unsupported API version or invalid plugin ID/version")
	}
	if len(m.Description) == 0 || len(m.Description) > 512 || len(m.Author) == 0 || len(m.Author) > 128 || len(m.License) == 0 || len(m.License) > 128 {
		return fmt.Errorf("description, author, and license are required and bounded")
	}
	if len(m.Module) == 0 || len(m.Module) > 256 || strings.ContainsRune(m.Module, 0) || len(m.SHA256) != 64 {
		return fmt.Errorf("invalid module path or SHA-256")
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil || m.SHA256 != strings.ToLower(m.SHA256) {
		return fmt.Errorf("SHA-256 must be 64 lowercase hexadecimal characters")
	}
	if len(m.Permissions) != 1 || m.Permissions[0] != "scan.read" {
		return fmt.Errorf("version 1 requires exactly the scan.read permission")
	}
	if m.Match.Transport != "tcp" || len(m.Match.States) != 1 || m.Match.States[0] != "open" || len(m.Match.Services) > 4 {
		return fmt.Errorf("version 1 matches open TCP results only")
	}
	seen := map[string]bool{}
	for _, name := range m.Match.Services {
		if (name != "http" && name != "https" && name != "ssh" && name != "tls") || seen[name] {
			return fmt.Errorf("invalid or duplicate service match %q", name)
		}
		seen[name] = true
	}
	if len(m.Parameters) > 32 {
		return fmt.Errorf("at most 32 parameters are allowed")
	}
	for name, parameter := range m.Parameters {
		if !identifier.MatchString(name) || strings.Contains(name, ".") {
			return fmt.Errorf("invalid parameter name %q", name)
		}
		if err := parameter.validateDefinition(); err != nil {
			return fmt.Errorf("parameter %s: %w", name, err)
		}
	}
	return nil
}

func (p Parameter) validateDefinition() error {
	switch p.Type {
	case "integer":
		if p.MaxLength != nil || p.Minimum != nil && (*p.Minimum < -(1<<53) || *p.Minimum > 1<<53) || p.Maximum != nil && (*p.Maximum < -(1<<53) || *p.Maximum > 1<<53) || p.Minimum != nil && p.Maximum != nil && *p.Minimum > *p.Maximum {
			return fmt.Errorf("invalid integer bounds")
		}
	case "string":
		if p.Minimum != nil || p.Maximum != nil || p.MaxLength != nil && (*p.MaxLength < 1 || *p.MaxLength > 4096) {
			return fmt.Errorf("invalid string bounds")
		}
	case "boolean":
		if p.Minimum != nil || p.Maximum != nil || p.MaxLength != nil {
			return fmt.Errorf("boolean parameters cannot have bounds")
		}
	default:
		return fmt.Errorf("type must be integer, string, or boolean")
	}
	data, err := json.Marshal(p.Default)
	if err != nil {
		return err
	}
	return p.validateValue(data)
}

func (p Parameter) validateValue(data json.RawMessage) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("null parameter value is unsupported")
	}
	switch p.Type {
	case "integer":
		var value int64
		if err := json.Unmarshal(data, &value); err != nil {
			return fmt.Errorf("expected an integer")
		}
		if value < -(1<<53) || value > 1<<53 || p.Minimum != nil && value < *p.Minimum || p.Maximum != nil && value > *p.Maximum {
			return fmt.Errorf("integer outside allowed range")
		}
	case "string":
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return fmt.Errorf("expected a string")
		}
		limit := 256
		if p.MaxLength != nil {
			limit = *p.MaxLength
		}
		if len(value) > limit {
			return fmt.Errorf("string exceeds %d bytes", limit)
		}
	case "boolean":
		var value bool
		if err := json.Unmarshal(data, &value); err != nil {
			return fmt.Errorf("expected a boolean")
		}
	}
	return nil
}

func (m Manifest) parameters(values map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	result := make(map[string]json.RawMessage, len(m.Parameters))
	for key, parameter := range m.Parameters {
		data, _ := json.Marshal(parameter.Default)
		result[key] = data
	}
	for key, value := range values {
		parameter, ok := m.Parameters[key]
		if !ok {
			return nil, fmt.Errorf("unknown parameter %s.%s", m.ID, key)
		}
		if err := parameter.validateValue(value); err != nil {
			return nil, fmt.Errorf("parameter %s.%s: %w", m.ID, key, err)
		}
		result[key] = value
	}
	return result, nil
}

func parseOverrides(raw []string, manifests []Manifest) (map[string]map[string]json.RawMessage, error) {
	result := map[string]map[string]json.RawMessage{}
	byID := map[string]Manifest{}
	for _, m := range manifests {
		byID[m.ID] = m
	}
	if len(raw) > 128 {
		return nil, fmt.Errorf("at most 128 parameter overrides")
	}
	for _, item := range raw {
		key, value, ok := strings.Cut(item, "=")
		separator := strings.LastIndex(key, ".")
		id, name := "", ""
		if separator >= 0 {
			id, name = key[:separator], key[separator+1:]
		}
		m, exists := byID[id]
		if !ok || separator < 0 || !exists || len(value) > 4096 {
			return nil, fmt.Errorf("invalid script parameter %q", key)
		}
		parameter, exists := m.Parameters[name]
		if !exists {
			return nil, fmt.Errorf("unknown parameter %s", key)
		}
		data := []byte(value)
		if parameter.Type == "string" {
			data, _ = json.Marshal(value)
		}
		if err := parameter.validateValue(data); err != nil {
			return nil, fmt.Errorf("parameter %s: %w", key, err)
		}
		if result[id] == nil {
			result[id] = map[string]json.RawMessage{}
		}
		if _, exists := result[id][name]; exists {
			return nil, fmt.Errorf("duplicate parameter override %s", key)
		}
		result[id][name] = data
	}
	return result, nil
}

func matches(m Manifest, result model.Result) bool {
	if result.State != model.Open || result.Target.Transport != model.TCP {
		return false
	}
	if len(m.Match.Services) == 0 {
		return true
	}
	if result.Service == nil {
		return false
	}
	for _, name := range m.Match.Services {
		if result.Service.Name == name {
			return true
		}
	}
	return false
}

// ResolveField resolves a scalar JSON Pointer; array indices and escaped keys
// are supported. Requiring an existing field prevents invented evidence paths.
func resolveField(root any, path string) bool {
	if len(path) > 256 || !strings.HasPrefix(path, "/") {
		return false
	}
	value := root
	for _, part := range strings.Split(path[1:], "/") {
		for i := 0; i < len(part); i++ {
			if part[i] == '~' {
				if i+1 >= len(part) || part[i+1] != '0' && part[i+1] != '1' {
					return false
				}
				i++
			}
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch node := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = node[part]
			if !ok {
				return false
			}
		case []any:
			// JSON Pointer array indices are unsigned decimal integers without
			// leading zeros. Atoi alone also accepts +0, -0, and 00.
			if part == "" || len(part) > 1 && part[0] == '0' {
				return false
			}
			for _, digit := range part {
				if digit < '0' || digit > '9' {
					return false
				}
			}
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) {
				return false
			}
			value = node[index]
		default:
			return false
		}
	}
	switch value.(type) {
	case map[string]any, []any:
		return false
	}
	return true
}
