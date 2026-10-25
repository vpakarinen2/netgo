package jsonwire

import "testing"

func TestStrictJSON(t *testing.T) {
	for _, data := range []string{`{}`, `{"value":"ok"}`} {
		var value struct {
			Value string `json:"value"`
		}
		if err := Decode([]byte(data), &value); err != nil {
			t.Fatal(err)
		}
	}
	for _, data := range []string{`[]`, `null`, `{} {}`, `{"value":"a","value":"b"}`, `{"value":"a","Value":"b"}`, `{"extra":1}`, "{\"value\":\"\xff\"}"} {
		var value struct {
			Value string `json:"value"`
		}
		if err := Decode([]byte(data), &value); err == nil {
			t.Errorf("accepted ambiguous/invalid JSON %q", data)
		}
	}
}
