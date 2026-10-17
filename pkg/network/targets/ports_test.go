package targets

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("443, 80,79-81,80,65535")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{79, 80, 81, 443, 65535}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	all, err := ParsePorts("1-65535")
	if err != nil || len(all) != 65535 || all[0] != 1 || all[len(all)-1] != 65535 {
		t.Fatalf("full port range failed: count=%d, err=%v", len(all), err)
	}
}

func TestParsePortsRejectsInvalidInput(t *testing.T) {
	for _, spec := range []string{"", " ", "0", "65536", "-1", "+22", "80,", ",80", "80,,443", "90-80", "1-2-3", "http", "1.5", "1-", "-", "1e2"} {
		t.Run(spec, func(t *testing.T) {
			if _, err := ParsePorts(spec); err == nil {
				t.Fatalf("accepted %q", spec)
			}
		})
	}
}

func FuzzParsePorts(f *testing.F) {
	for _, seed := range []string{"22,80,443", "1-65535", "", "65536", "80-22", "1-3,2"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		ports, err := ParsePorts(spec)
		if err != nil {
			return
		}
		if len(ports) == 0 {
			t.Fatal("successful parse returned no ports")
		}
		for i, port := range ports {
			if port == 0 || (i > 0 && ports[i-1] >= port) {
				t.Fatalf("ports are not positive, sorted, and unique: %v", ports)
			}
		}
	})
}
