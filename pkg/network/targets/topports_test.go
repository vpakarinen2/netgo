package targets

import "testing"

func TestTopPorts(t *testing.T) {
	var previous []uint16
	for _, count := range []int{10, 100, 1000} {
		ports, err := TopPorts(count)
		if err != nil || len(ports) != count {
			t.Fatalf("preset %d: count=%d err=%v", count, len(ports), err)
		}
		set := make(map[uint16]bool, count)
		for i, port := range ports {
			if port == 0 || i > 0 && ports[i-1] >= port {
				t.Fatalf("preset %d is not sorted and unique: %v", count, ports)
			}
			set[port] = true
		}
		for _, port := range previous {
			if !set[port] {
				t.Fatalf("preset %d lost smaller preset's port %d", count, port)
			}
		}
		for _, port := range []uint16{22, 80, 443, 3389} {
			if !set[port] {
				t.Fatalf("preset %d missing common port %d", count, port)
			}
		}
		previous = append([]uint16(nil), ports...)
		ports[0] = 0
		fresh, _ := TopPorts(count)
		if fresh[0] == 0 {
			t.Fatal("caller can mutate embedded preset")
		}
	}
	for _, count := range []int{-1, 0, 1, 11, 99, 101, 999, 1001, 65535} {
		if _, err := TopPorts(count); err == nil {
			t.Fatalf("accepted unsupported preset %d", count)
		}
	}
}
