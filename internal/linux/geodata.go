package linux

import (
	"context"
	"errors"
	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"github.com/ZarpVPN/Zarp-Linux/internal/geodata"
	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type GeoInfo struct {
	Categories int       `json:"categories"`
	Updated    time.Time `json:"updated"`
	URL        string    `json:"url,omitempty"`
	Bundled    bool      `json:"bundled,omitempty"`
}

func (b *Backend) GeographicStatus() any { return b.GeoStatus() }
func (b *Backend) GeoStatus() map[string]GeoInfo {
	result := map[string]GeoInfo{}
	for _, kind := range []string{"geoip", "geosite"} {
		var info GeoInfo
		if storage.Read(filepath.Join(b.State, "geodata", kind+".json"), &info) != nil {
			info.Bundled = kind == "geoip"
		}
		result[kind] = info
	}
	return result
}
func (b *Backend) DownloadGeo(ctx context.Context, kind, rawURL string, cfg core.Config, emit func(string)) error {
	if kind != "geoip" && kind != "geosite" {
		return errors.New("invalid_geographic_database_kind")
	}
	data, err := b.Download(ctx, rawURL, 64<<20, cfg, emit)
	if err != nil {
		return err
	}
	db, err := geodata.Parse(data, kind)
	if err != nil {
		return err
	}
	dir := filepath.Join(b.State, "geodata")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err = writeAtomic(filepath.Join(dir, kind+".dat"), data); err != nil {
		return err
	}
	return storage.Write(filepath.Join(dir, kind+".json"), GeoInfo{Categories: len(db), Updated: time.Now().UTC(), URL: rawURL})
}
func writeAtomic(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".download-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func (b *Backend) expandRoutes(routes []core.Route) ([]core.Route, error) {
	result := []core.Route{}
	loaded := map[string]geodata.Database{}
	for _, route := range routes {
		if route.Kind != "geoip" && route.Kind != "geosite" {
			result = append(result, route)
			continue
		}
		for _, value := range route.Values {
			category, attribute, _ := strings.Cut(value, "@")
			if route.Kind == "geoip" && category == "private" {
				values, _ := geodata.Builtin("private")
				result = append(result, core.Route{Action: route.Action, Kind: "ip_cidr", Values: values})
				continue
			}
			db, seen := loaded[route.Kind]
			if !seen {
				file, err := os.Open(filepath.Join(b.State, "geodata", route.Kind+".dat"))
				if err == nil {
					var data []byte
					data, err = boundedRead(file, 64<<20)
					file.Close()
					if err == nil {
						db, err = geodata.Parse(data, route.Kind)
					}
				}
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return nil, err
				}
				loaded[route.Kind] = db
			}
			if db == nil && route.Kind == "geoip" {
				values, err := geodata.Builtin(category)
				if err != nil {
					return nil, err
				}
				result = append(result, core.Route{Action: route.Action, Kind: "ip_cidr", Values: values})
				continue
			}
			entry, ok := db[category]
			if !ok {
				return nil, errors.New("geographic_category_missing_download_database")
			}
			grouped := map[string][]string{}
			for _, record := range entry.Records {
				if route.Kind == "geoip" {
					cidr, err := geodata.CIDR(record)
					if err != nil {
						return nil, err
					}
					grouped["ip_cidr"] = append(grouped["ip_cidr"], cidr)
				} else {
					domain, err := geodata.ParseDomain(record)
					if err != nil {
						return nil, err
					}
					if attribute != "" {
						negate := strings.HasPrefix(attribute, "!")
						key := strings.TrimPrefix(attribute, "!")
						if domain.Attributes[key] == negate {
							continue
						}
					}
					grouped[domain.Kind] = append(grouped[domain.Kind], domain.Value)
				}
			}
			if len(grouped) == 0 {
				return nil, errors.New("geographic_category_has_no_matching_records")
			}
			keys := []string{}
			for key := range grouped {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			for _, key := range keys {
				values := grouped[key]
				slices.Sort(values)
				values = slices.Compact(values)
				result = append(result, core.Route{Action: route.Action, Kind: key, Values: values, Invert: entry.Inverse})
			}
		}
	}
	return result, nil
}
func boundedRead(reader io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("file_size_exceeded")
	}
	return data, nil
}
