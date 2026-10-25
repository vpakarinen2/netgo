// Build the example command modules and write manifests with their exact hashes.
package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	if err := build(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build() error {
	for _, name := range []string{"tls-expiry", "tls-hostname", "tls-certificate", "ssh-banner"} {
		dir := filepath.Join("examples", "plugins", name)
		module := filepath.Join(dir, name+".wasm")
		command := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-ldflags=-s -w", "-o", module, "./"+filepath.ToSlash(dir))
		command.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			return err
		}
		data, err := os.ReadFile(module)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		services := "[https, tls]"
		parameters := "parameters: {}\n"
		description := "Report certificate hostname mismatches"
		switch name {
		case "tls-certificate":
			description = "Report collected leaf certificate information"
		case "tls-expiry":
			description = "Report certificates expiring soon"
			parameters = "parameters:\n  days:\n    type: integer\n    default: 30\n    minimum: 1\n    maximum: 365\n"
		case "ssh-banner":
			description = "Match the software claim in an SSH greeting"
			services = "[ssh]"
			parameters = "parameters:\n  contains:\n    type: string\n    default: OpenSSH\n    max_length: 128\n"
		}
		manifest := fmt.Sprintf("api_version: netgo.script/v1\nid: %s\nversion: 0.1.0\ndescription: %s\nauthor: Netgo contributors\nlicense: Apache-2.0\nmodule: %s.wasm\nsha256: %x\npermissions: [scan.read]\nmatch:\n  transport: tcp\n  states: [open]\n  services: %s\n%s", name, description, name, digest, services, parameters)
		if err := os.WriteFile(filepath.Join(dir, "plugin.yaml"), []byte(manifest), 0644); err != nil {
			return err
		}
		installed := filepath.Join("bin", "scripts", name)
		if err := os.MkdirAll(installed, 0755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(installed, name+".wasm"), data, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(installed, "plugin.yaml"), []byte(manifest), 0644); err != nil {
			return err
		}
		fmt.Println("Built", module, "and installed", installed)
	}
	return nil
}
