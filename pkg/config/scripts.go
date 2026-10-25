package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/vpakarinen2/netgo/pkg/plugins"
)

type Scripts struct {
	Paths       []string      `mapstructure:"paths" json:"paths"`
	Parameters  []string      `mapstructure:"parameters" json:"parameters"`
	Timeout     time.Duration `mapstructure:"timeout" json:"-"`
	Concurrency int           `mapstructure:"concurrency" json:"concurrency"`
	MemoryMiB   int           `mapstructure:"memory_mib" json:"memory_mib"`
}

func (s Scripts) MarshalJSON() ([]byte, error) {
	type plain Scripts
	return json.Marshal(struct {
		plain
		Timeout string `json:"timeout"`
	}{plain(s), s.Timeout.String()})
}

func loadScripts(v *viper.Viper) (s Scripts, err error) {
	if s.Paths, err = stringListValue(v, "scripts.paths"); err != nil {
		return
	}
	if s.Parameters, err = stringListValue(v, "scripts.parameters"); err != nil {
		return
	}
	if s.Concurrency, err = intValue(v, "scripts.concurrency"); err != nil {
		return
	}
	if s.MemoryMiB, err = intValue(v, "scripts.memory_mib"); err != nil {
		return
	}
	value, err := stringValue(v, "scripts.timeout")
	if err != nil {
		return
	}
	s.Timeout, err = time.ParseDuration(value)
	return
}

func (s Scripts) Validate() error {
	if err := (plugins.Limits{Timeout: s.Timeout, MemoryMiB: s.MemoryMiB}).Validate(); err != nil {
		return err
	}
	if s.Concurrency < 1 || s.Concurrency > 16 || s.Concurrency*s.MemoryMiB > 512 {
		return fmt.Errorf("scripts require 1-16 workers and at most 512 MiB aggregate guest linear memory")
	}
	if len(s.Paths) > plugins.MaxPlugins || len(s.Parameters) > 128 {
		return fmt.Errorf("too many script selections or parameters")
	}
	if len(s.Paths) == 0 && len(s.Parameters) > 0 {
		return fmt.Errorf("script parameters require a selected script")
	}
	for _, path := range s.Paths {
		if path == "" || len(path) > 4096 || strings.ContainsRune(path, 0) {
			return fmt.Errorf("invalid script manifest path")
		}
	}
	return nil
}

func stringListValue(v *viper.Viper, key string) ([]string, error) {
	var result []string
	switch value := v.Get(key).(type) {
	case []string:
		result = value
	case []any:
		for _, entry := range value {
			text, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("%s must be a string array", key)
			}
			result = append(result, text)
		}
	case string:
		if strings.TrimSpace(value) == "null" {
			return nil, fmt.Errorf("%s must be an array, not null", key)
		}
		if err := json.Unmarshal([]byte(value), &result); err != nil {
			return nil, fmt.Errorf("%s must be a JSON string array in the environment", key)
		}
	default:
		return nil, fmt.Errorf("%s must be a string array", key)
	}
	if result == nil {
		result = []string{}
	}
	return result, nil
}
