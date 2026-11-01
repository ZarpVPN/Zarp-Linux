// Package geodata reads the bounded V2Ray/Xray geographic database format.
// Behaviour and validation follow the MIT Windows Zarp GeoDat implementation.
package geodata

import (
	"embed"
	"encoding/binary"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Country ranges originate from ipverse/country-ip-blocks (CC0), as in Windows Zarp.
//
//go:embed data/*.txt
var ranges embed.FS

type Field struct {
	Number, Wire int
	Data         []byte
	Value        uint64
}
type Entry struct {
	Records [][]byte
	Inverse bool
}
type Database map[string]Entry
type Domain struct {
	Kind, Value string
	Attributes  map[string]bool
}

var tag = regexp.MustCompile(`^[a-z0-9_!.\-]{1,128}$`)
var bad = errors.New("invalid_geographic_database")

func Walk(data []byte, visit func(Field) error) error {
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 || key>>3 == 0 || key>>3 > 1<<29 {
			return bad
		}
		data = data[n:]
		f := Field{Number: int(key >> 3), Wire: int(key & 7)}
		switch f.Wire {
		case 0:
			value, count := binary.Uvarint(data)
			if count <= 0 {
				return bad
			}
			f.Value = value
			data = data[count:]
		case 1:
			if len(data) < 8 {
				return bad
			}
			data = data[8:]
		case 2:
			length, count := binary.Uvarint(data)
			if count <= 0 || length > uint64(len(data)-count) {
				return bad
			}
			data = data[count:]
			f.Data = data[:int(length)]
			data = data[int(length):]
		case 5:
			if len(data) < 4 {
				return bad
			}
			data = data[4:]
		default:
			return bad
		}
		if err := visit(f); err != nil {
			return err
		}
	}
	return nil
}
func Parse(data []byte, kind string) (Database, error) {
	if (kind != "geoip" && kind != "geosite") || len(data) == 0 || len(data) > 64<<20 {
		return nil, bad
	}
	db := Database{}
	records := 0
	err := Walk(data, func(f Field) error {
		if f.Number != 1 {
			return nil
		}
		if f.Wire != 2 {
			return bad
		}
		name := ""
		e := Entry{}
		if err := Walk(f.Data, func(v Field) error {
			switch v.Number {
			case 1:
				if v.Wire != 2 || !utf8.Valid(v.Data) {
					return bad
				}
				name = strings.ToLower(string(v.Data))
			case 2:
				if v.Wire != 2 || records >= 2000000 {
					return bad
				}
				records++
				if kind == "geoip" {
					if _, err := CIDR(v.Data); err != nil {
						return err
					}
				} else {
					if _, err := ParseDomain(v.Data); err != nil {
						return err
					}
				}
				e.Records = append(e.Records, v.Data)
			case 3:
				if kind == "geoip" {
					if v.Wire != 0 {
						return bad
					}
					e.Inverse = v.Value != 0
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if !tag.MatchString(name) || len(e.Records) == 0 || len(db) >= 20000 {
			return bad
		}
		if _, exists := db[name]; exists {
			return bad
		}
		db[name] = e
		return nil
	})
	if err != nil || len(db) == 0 {
		return nil, bad
	}
	return db, nil
}
func CIDR(data []byte) (string, error) {
	var ip []byte
	prefix := uint64(0)
	err := Walk(data, func(f Field) error {
		if f.Number == 1 {
			if f.Wire != 2 {
				return bad
			}
			ip = f.Data
		}
		if f.Number == 2 {
			if f.Wire != 0 {
				return bad
			}
			prefix = f.Value
		}
		return nil
	})
	addr, ok := netip.AddrFromSlice(ip)
	if err != nil || !ok || prefix > uint64(addr.BitLen()) {
		return "", bad
	}
	return netip.PrefixFrom(addr, int(prefix)).Masked().String(), nil
}
func ParseDomain(data []byte) (Domain, error) {
	d := Domain{Attributes: map[string]bool{}}
	kind := uint64(0)
	err := Walk(data, func(f Field) error {
		switch f.Number {
		case 1:
			if f.Wire != 0 {
				return bad
			}
			kind = f.Value
		case 2:
			if f.Wire != 2 || !utf8.Valid(f.Data) {
				return bad
			}
			d.Value = string(f.Data)
		case 3:
			if f.Wire != 2 {
				return bad
			}
			key := ""
			present := true
			if err := Walk(f.Data, func(a Field) error {
				if a.Number == 1 {
					if a.Wire != 2 {
						return bad
					}
					key = strings.ToLower(string(a.Data))
				}
				if a.Number == 2 {
					if a.Wire != 0 {
						return bad
					}
					present = a.Value != 0
				}
				return nil
			}); err != nil {
				return err
			}
			if !tag.MatchString(key) {
				return bad
			}
			d.Attributes[key] = present
		}
		return nil
	})
	if err != nil || kind > 3 || len(d.Value) == 0 || len(d.Value) > 4096 || strings.ContainsAny(d.Value, "\x00\r\n") {
		return d, bad
	}
	d.Kind = []string{"domain_keyword", "domain_regex", "domain_suffix", "domain"}[kind]
	return d, nil
}
func Builtin(category string) ([]string, error) {
	if category == "private" {
		return []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}, nil
	}
	if category != "ru" && category != "ir" && category != "cn" {
		return nil, errors.New("geographic_category_missing")
	}
	data, err := ranges.ReadFile("data/" + category + ".txt")
	if err != nil {
		return nil, err
	}
	var result []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, bad
		}
		result = append(result, prefix.Masked().String())
	}
	return result, nil
}
