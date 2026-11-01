package geodata

import (
	"encoding/binary"
	"testing"
)

func blob(field byte, data []byte) []byte {
	out := []byte{field<<3 | 2}
	out = binary.AppendUvarint(out, uint64(len(data)))
	return append(out, data...)
}
func TestParsesIPv4AndSiteAttributes(t *testing.T) {
	cidr := append(blob(1, []byte{1, 2, 3, 4}), 0x10, 24)
	entry := append(blob(1, []byte("ru")), blob(2, cidr)...)
	db, err := Parse(blob(1, entry), "geoip")
	if err != nil {
		t.Fatal(err)
	}
	network, err := CIDR(db["ru"].Records[0])
	if err != nil || network != "1.2.3.0/24" {
		t.Fatal(network, err)
	}
	attr := append(blob(1, []byte("ads")), 0x10, 1)
	domain := append([]byte{8, 2}, blob(2, []byte("example.com"))...)
	domain = append(domain, blob(3, attr)...)
	entry = append(blob(1, []byte("test")), blob(2, domain)...)
	db, err = Parse(blob(1, entry), "geosite")
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseDomain(db["test"].Records[0])
	if err != nil || d.Kind != "domain_suffix" || d.Value != "example.com" || !d.Attributes["ads"] {
		t.Fatal(d, err)
	}
}
func TestRejectsTruncatedDuplicateAndInvalidGeographicData(t *testing.T) {
	good := blob(1, append(blob(1, []byte("ru")), blob(2, append(blob(1, []byte{1, 2, 3, 4}), 0x10, 24))...))
	for _, data := range [][]byte{nil, {0xff, 0xff}, good[:len(good)-1], append(append([]byte{}, good...), good...)} {
		if _, err := Parse(data, "geoip"); err == nil {
			t.Fatalf("invalid database accepted: %x", data)
		}
	}
	for _, kind := range []string{"private", "ru", "ir", "cn"} {
		ranges, err := Builtin(kind)
		if err != nil || len(ranges) == 0 {
			t.Fatal(kind, err)
		}
	}
	if _, err := Builtin("../outside"); err == nil {
		t.Fatal("path accepted as category")
	}
}
