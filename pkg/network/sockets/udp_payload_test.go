package sockets

import (
	"bytes"
	"testing"
)

func TestUDPProbeSelectionAndValidation(t *testing.T) {
	for port, kind := range map[uint16]string{53: "dns", 123: "ntp", 161: "empty"} {
		probe, err := makeUDPPayload("auto", port)
		if err != nil || probe.kind != kind {
			t.Fatalf("port %d selected %+v %v", port, probe, err)
		}
	}
	if _, err := makeUDPPayload("invalid", 53); err == nil {
		t.Fatal("invalid UDP probe accepted")
	}
	probe, err := makeUDPPayload("ntp", 123)
	if err != nil {
		t.Fatal(err)
	}
	response := ntpReply(probe.data)
	response[1] = 0
	copy(response[12:16], "RATE")
	if ok, service := probe.match(response); !ok || service.Name != "ntp" || len(service.Evidence) != 3 {
		t.Fatal("NTP kiss-of-death response lost")
	}
	response[0] = 4<<3 | 3
	if ok, _ := probe.match(response); ok {
		t.Fatal("client-mode NTP packet matched as a server")
	}
}

func FuzzUDPReplyMatching(f *testing.F) {
	dnsProbe, err := makeUDPPayload("dns", 53)
	if err != nil {
		f.Fatal(err)
	}
	dnsProbe.data[0], dnsProbe.data[1] = 0x12, 0x34
	ntpProbe, err := makeUDPPayload("ntp", 123)
	if err != nil {
		f.Fatal(err)
	}
	copy(ntpProbe.data[40:48], bytes.Repeat([]byte{42}, 8))
	dnsResponse := append([]byte(nil), dnsProbe.data...)
	dnsResponse[2] |= 128
	for _, seed := range [][]byte{nil, {1, 2, 3}, dnsResponse, ntpReply(ntpProbe.data), bytes.Repeat([]byte{255}, 48)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			data = data[:65535]
		}
		dnsData := append([]byte(nil), data...)
		if len(dnsData) >= 2 {
			copy(dnsData[:2], dnsProbe.data[:2])
		}
		if ok, service := dnsProbe.match(dnsData); ok && (service == nil || service.Name != "dns") {
			t.Fatal("DNS match without DNS evidence")
		}
		ntpData := append([]byte(nil), data...)
		if len(ntpData) >= 48 {
			copy(ntpData[24:32], ntpProbe.data[40:48])
		}
		if ok, service := ntpProbe.match(ntpData); ok && (service == nil || service.Name != "ntp") {
			t.Fatal("NTP match without NTP evidence")
		}
	})
}
