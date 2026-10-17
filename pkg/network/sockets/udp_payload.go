package sockets

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	"github.com/miekg/dns"

	"github.com/vpakarinen2/netgo/pkg/model"
)

// UDP probes are small single-datagram requests. DNS recursion is disabled;
// NTP uses ordinary client mode, not control/monitor queries.
type udpPayload struct {
	kind string
	data []byte
}

func makeUDPPayload(kind string, port uint16) (udpPayload, error) {
	if kind == "auto" {
		switch port {
		case 53:
			kind = "dns"
		case 123:
			kind = "ntp"
		default:
			kind = "empty"
		}
	}
	probe := udpPayload{kind: kind}
	switch kind {
	case "empty":
		probe.data = []byte{}
	case "dns":
		var random [2]byte
		if _, err := rand.Read(random[:]); err != nil {
			return probe, err
		}
		message := &dns.Msg{MsgHdr: dns.MsgHdr{Id: binary.BigEndian.Uint16(random[:])}, Question: []dns.Question{{Name: ".", Qtype: dns.TypeNS, Qclass: dns.ClassINET}}}
		var err error
		probe.data, err = message.Pack()
		if err != nil {
			return probe, err
		}
	case "ntp":
		probe.data = make([]byte, 48)
		probe.data[0], probe.data[2] = 4<<3|3, 6 // version 4, client mode, 64s poll
		binary.BigEndian.PutUint32(probe.data[40:44], uint32(time.Now().Unix()+2208988800))
		if _, err := rand.Read(probe.data[44:48]); err != nil {
			return probe, err
		}
	default:
		return probe, fmt.Errorf("UDP probe must be auto, empty, dns, or ntp")
	}
	return probe, nil
}

func (p udpPayload) match(data []byte) (bool, *model.Service) {
	switch p.kind {
	case "empty":
		return true, nil // even an empty datagram is a reply
	case "dns":
		if len(data) < 12 || len(p.data) < 2 || !bytes.Equal(data[:2], p.data[:2]) {
			return false, nil
		}
		var message dns.Msg
		if err := message.Unpack(data); err != nil || !message.Response || message.Opcode != dns.OpcodeQuery || len(message.Question) != 1 {
			return false, nil
		}
		question := message.Question[0]
		if question.Name != "." || question.Qtype != dns.TypeNS || question.Qclass != dns.ClassINET {
			return false, nil
		}
		return true, &model.Service{Name: "dns", Evidence: []model.Evidence{{Kind: "dns_rcode", Value: dns.RcodeToString[message.Rcode]}, {Kind: "dns_question", Value: ". IN NS"}}}
	case "ntp":
		if len(data) < 48 || len(p.data) != 48 || data[0]&7 != 4 || (data[0]>>3&7 != 3 && data[0]>>3&7 != 4) || data[1] > 16 || !bytes.Equal(data[24:32], p.data[40:48]) {
			return false, nil
		}
		evidence := []model.Evidence{{Kind: "ntp_version", Value: strconv.Itoa(int(data[0] >> 3 & 7))}, {Kind: "ntp_stratum", Value: strconv.Itoa(int(data[1]))}}
		if data[1] == 0 {
			evidence = append(evidence, model.Evidence{Kind: "ntp_kiss_code", Value: fmt.Sprintf("%q", data[12:16])})
		}
		return true, &model.Service{Name: "ntp", Evidence: evidence}
	default:
		return false, nil
	}
}
