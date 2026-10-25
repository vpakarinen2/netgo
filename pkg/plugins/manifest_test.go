package plugins

import "testing"

func TestManifestsDoNotExposeEngineState(t *testing.T) {
	minimum, maximum, maxLength := int64(1), int64(365), 128
	engine := &Engine{bundles: []bundle{{manifest: Manifest{
		ID: "fixture", Permissions: []string{"scan.read"},
		Match: Match{Transport: "tcp", States: []string{"open"}, Services: []string{"https"}},
		Parameters: map[string]Parameter{
			"days": {Type: "integer", Default: 30, Minimum: &minimum, Maximum: &maximum},
			"name": {Type: "string", Default: "fixture", MaxLength: &maxLength},
		},
	}}}}
	first := engine.Manifests()[0]
	first.Permissions[0] = "modified"
	first.Match.States[0] = "closed"
	first.Match.Services[0] = "ssh"
	*first.Parameters["days"].Minimum = -100
	*first.Parameters["days"].Maximum = 999
	*first.Parameters["name"].MaxLength = 999
	delete(first.Parameters, "name")
	second := engine.Manifests()[0]
	if second.Permissions[0] != "scan.read" || second.Match.States[0] != "open" || second.Match.Services[0] != "https" || *second.Parameters["days"].Minimum != 1 || *second.Parameters["days"].Maximum != 365 {
		t.Fatalf("caller changed engine manifest: %+v", second)
	}
	if name, ok := second.Parameters["name"]; !ok || *name.MaxLength != 128 {
		t.Fatal("caller changed engine parameters")
	}
}

func TestEvidencePointerArrayIndicesAreCanonical(t *testing.T) {
	root := map[string]any{"evidence": []any{map[string]any{"value": "banner"}}, "keys": map[string]any{"00": "valid object key", "+0": "also valid"}}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/evidence/0/value", true},
		{"/evidence/00/value", false},
		{"/evidence/+0/value", false},
		{"/evidence/-0/value", false},
		{"/evidence/-/value", false},
		{"/evidence/1/value", false},
		{"/evidence/999999999999999999999/value", false},
		{"/keys/00", true},
		{"/keys/+0", true},
	} {
		if got := resolveField(root, tc.path); got != tc.want {
			t.Errorf("resolveField(%q) = %t, want %t", tc.path, got, tc.want)
		}
	}
}
