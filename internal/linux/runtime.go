package linux

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
)

var cryptoReader = rand.Reader

func hexString(b []byte) string { return hex.EncodeToString(b) }

type Manifest struct {
	Schema   int               `json:"schema"`
	Versions map[string]string `json:"versions"`
	Files    map[string]string `json:"files"`
}
type Runtime struct {
	Dir         string
	Manifest    Manifest
	Fingerprint string
}

func LoadRuntime(dir string) (*Runtime, error) {
	resolved, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = trustedPath(resolved, true); err != nil {
		return nil, err
	}
	var manifest Manifest
	if err = storage.Read(filepath.Join(resolved, "integrity.json"), &manifest); err != nil {
		return nil, errors.New("runtime_manifest_unavailable")
	}
	if manifest.Schema != 1 || len(manifest.Files) < 10 || len(manifest.Files) > 128 {
		return nil, errors.New("runtime_manifest_invalid")
	}
	r := &Runtime{Dir: resolved, Manifest: manifest, Fingerprint: core.Fingerprint(manifest)}
	for name, digest := range manifest.Files {
		if filepath.IsAbs(name) || strings.Contains(name, "\\") || filepath.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || len(digest) != 64 {
			return nil, errors.New("runtime_manifest_invalid")
		}
		path := filepath.Join(resolved, name)
		if err = trustedPath(path, false); err != nil {
			return nil, err
		}
		file, openErr := os.Open(path)
		if openErr != nil {
			return nil, errors.New("runtime_file_missing")
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, io.LimitReader(file, 128*1024*1024+1))
		_ = file.Close()
		if copyErr != nil || hex.EncodeToString(h.Sum(nil)) != digest {
			return nil, errors.New("runtime_integrity_failed")
		}
	}
	for _, name := range []string{"nfqws2", "sing-box", "xray", "lua/zapret-lib.lua", "lua/zapret-antidpi.lua", "lua/zarp-observe.lua", "blobs/quic_google.bin", "blobs/quic_vk.bin", "blobs/tls_google.bin", "blobs/tls_vk.bin", "blobs/tls_gosuslugi.bin", "blobs/stun.bin"} {
		if _, ok := manifest.Files[name]; !ok {
			return nil, errors.New("runtime_manifest_incomplete")
		}
	}
	return r, nil
}

func trustedPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("runtime_path_unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return errors.New("runtime_path_not_regular")
	}
	if os.Geteuid() == 0 {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("runtime_must_be_root_owned_and_readonly")
		}
	}
	for parent := filepath.Dir(path); parent != "/" && parent != "."; parent = filepath.Dir(parent) {
		p, err := os.Lstat(parent)
		if err != nil || !p.IsDir() || p.Mode()&os.ModeSymlink != 0 {
			return errors.New("runtime_parent_invalid")
		}
		if os.Geteuid() == 0 {
			st, ok := p.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 || p.Mode().Perm()&0022 != 0 && p.Mode()&os.ModeSticky == 0 {
				return errors.New("runtime_parent_writable")
			}
		}
	}
	return nil
}

func (r *Runtime) Path(name string) string { return filepath.Join(r.Dir, name) }
