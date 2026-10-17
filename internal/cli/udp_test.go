package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/vpakarinen2/netgo/pkg/output"
)

func TestUDPCLIInlineDNSIdentification(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 512)
		n, peer, err := listener.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		var query dns.Msg
		if err := query.Unpack(buffer[:n]); err != nil {
			t.Error(err)
			return
		}
		response := new(dns.Msg)
		response.SetRcode(&query, dns.RcodeRefused)
		data, err := response.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = listener.WriteToUDP(data, peer)
	}()
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"127.0.0.1", "--transport", "udp", "--udp-probe", "dns", "-p", fmt.Sprint(listener.LocalAddr().(*net.UDPAddr).Port), "--format", "ndjson", "--quiet"})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&stdout)
	var result, summary output.Event
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if result.Result == nil || result.Result.Target.Transport != "udp" || result.Result.Method != "udp" || result.Result.State != "open" || result.Result.Service == nil || result.Result.Service.Name != "dns" || result.Result.UDP.Probe != "dns" || result.Result.Identification != nil {
		t.Fatalf("invalid UDP result: %+v", result.Result)
	}
	if summary.Summary == nil || summary.Summary.Open != 1 || summary.Summary.Status != "completed" {
		t.Fatalf("invalid UDP summary: %+v", summary.Summary)
	}
	<-done
}

func TestUDPCLISilenceIsOpenFilteredAndRetried(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"127.0.0.1", "--transport", "udp", "--udp-probe", "empty", "-p", fmt.Sprint(listener.LocalAddr().(*net.UDPAddr).Port), "--timeout", "40ms", "--retries", "1", "--format", "ndjson", "--quiet"})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&stdout)
	var result, summary output.Event
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if result.Result.State != "open|filtered" || result.Result.Attempts != 2 || summary.Summary.OpenFiltered != 1 || summary.Summary.Unknown != 0 || summary.Summary.Attempts != 2 {
		t.Fatalf("UDP ambiguity/retries lost: %+v %+v", result.Result, summary.Summary)
	}
	if err := decoder.Decode(&summary); err != io.EOF {
		t.Fatalf("unexpected trailing output: %v", err)
	}
}

func TestUDPCLIRejectsTCPServiceStage(t *testing.T) {
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"127.0.0.1", "--transport", "udp", "--service"})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "for TCP") || stdout.Len() != 0 {
		t.Fatalf("invalid UDP/service combination accepted: %v", err)
	}
}
