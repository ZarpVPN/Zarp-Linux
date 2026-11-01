package storage

import (
	"os"
	"testing"
)

func TestStrictJSONRejectsAmbiguousRequests(t *testing.T) {
	type document struct {
		Version int `json:"version"`
	}
	for _, data := range []string{`{"version":1,"version":2}`, `{"version":1,"\u0076ersion":2}`, `{"version":1,"unknown":true}`, `{"version":1} {"version":2}`, `{"version":1,"nested":{"x":1,"x":2}}`} {
		var value document
		if Decode([]byte(data), &value) == nil {
			t.Fatalf("accepted ambiguous JSON %s", data)
		}
	}
}
func TestAtomicPrivateStorage(t *testing.T) {
	path := t.TempDir() + "/private/config.json"
	value := map[string]string{"credential": "test-secret"}
	if err := Write(path, value); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("credential file is not private")
	}
	value["credential"] = "updated"
	if err = Write(path, value); err != nil {
		t.Fatal(err)
	}
	var loaded map[string]string
	if err = Read(path, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded["credential"] != "updated" {
		t.Fatal("atomic update lost data")
	}
}
