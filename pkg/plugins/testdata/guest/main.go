// Test-only hostile and well-behaved guest commands; never used by live scans.
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/plugins/sdk"
)

var count int
var memory [][]byte

func main() {
	request, err := sdk.ReadRequest(os.Stdin)
	if err != nil {
		panic(err)
	}
	mode, err := request.String("mode")
	if err != nil {
		panic(err)
	}
	switch mode {
	case "loop":
		for {
		}
	case "memory":
		for {
			memory = append(memory, make([]byte, 8*1024*1024))
			memory[len(memory)-1][0] = 1
		}
	case "stdout":
		for {
			fmt.Print(strings.Repeat("x", 8192))
		}
	case "stderr":
		for {
			fmt.Fprint(os.Stderr, strings.Repeat("x", 8192))
		}
	case "trap":
		panic("fixture trap")
	case "exit":
		os.Exit(3)
	case "invalid":
		fmt.Print("not json")
		return
	case "duplicate":
		fmt.Print(`{"api_version":"netgo.script/v1","outcome":"completed","outcome":"inconclusive","findings":[]}`)
		return
	case "unknown":
		fmt.Print(`{"api_version":"netgo.script/v1","outcome":"completed","host":"forged","findings":[]}`)
		return
	case "trailing":
		fmt.Print(`{"api_version":"netgo.script/v1","outcome":"completed","findings":[]} {}`)
		return
	case "utf8":
		_, _ = os.Stdout.Write([]byte{255})
		return
	case "deny":
		if os.Getenv("NETGO_PLUGIN_SECRET") != "" {
			panic("environment leaked")
		}
		if _, err := os.ReadFile("/etc/passwd"); err == nil {
			panic("host filesystem readable")
		}
		if file, err := os.Create("/netgo-plugin-denial-test"); err == nil {
			file.Close()
			panic("host filesystem writable")
		}
		if conn, err := net.DialTimeout("tcp", "127.0.0.1:9", 10*time.Millisecond); err == nil {
			conn.Close()
			panic("guest network available")
		}
	}
	count++
	message := fmt.Sprintf("%s:%d instance=%d", request.Result.Target.Address, request.Result.Target.Port, count)
	field := "/target/address"
	if mode == "missing" {
		field = "/service/invented"
	}
	response := sdk.Response{APIVersion: sdk.APIVersion, Outcome: "completed", Findings: []model.ScriptFinding{{ID: "fixture", Kind: "observation", Severity: "info", Message: message, EvidenceFields: []string{field}}}}
	// This command already consumed its request; encode the response directly.
	fmt.Printf("{\"api_version\":%q,\"outcome\":%q,\"findings\":[{\"id\":%q,\"kind\":%q,\"severity\":%q,\"message\":%q,\"evidence_fields\":[%q]}]}", response.APIVersion, response.Outcome, response.Findings[0].ID, response.Findings[0].Kind, response.Findings[0].Severity, response.Findings[0].Message, field)
}
