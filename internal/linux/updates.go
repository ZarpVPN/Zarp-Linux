package linux

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type updateAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}
type updateRelease struct {
	Tag    string        `json:"tag_name"`
	Assets []updateAsset `json:"assets"`
}
type updateCache struct {
	When    time.Time     `json:"when"`
	Current string        `json:"current"`
	Ahead   bool          `json:"ahead"`
	Release updateRelease `json:"release"`
}
type runtimeReference struct {
	Directory string `json:"directory"`
	Base      string `json:"base"`
}

var releaseTag = regexp.MustCompile(`^v[0-9]+(?:\.[0-9]+){1,3}$`)
var runtimeDirectory = regexp.MustCompile(`^zapret_[a-f0-9]{16}$`)

// Executable assets contain no credentials. Keep them outside the private state
// directory so nfqws2 can read its Lua files after dropping privileges.
func (b *Backend) runtimeUpdatesDir() string { return filepath.Clean(b.State) + "-runtime" }

func (b *Backend) CheckUpdates(ctx context.Context, cfg core.Config, emit func(string)) (core.Object, error) {
	b.mu.Lock()
	r := b.Runtime
	b.mu.Unlock()
	current := r.Manifest.Versions["zapret2"]
	short := current
	if len(short) > 12 {
		short = short[:12]
	}
	result := core.Object{"current": short, "available": ""}
	var cached updateCache
	if storage.Read(filepath.Join(b.State, "update-check.json"), &cached) != nil || cached.Current != current || time.Since(cached.When) > 12*time.Hour || cached.When.After(time.Now().Add(time.Hour)) {
		data, err := b.Download(ctx, "https://api.github.com/repos/bol-van/zapret2/releases/latest", 2<<20, cfg, emit)
		if err != nil {
			return nil, err
		}
		var release updateRelease
		if json.Unmarshal(data, &release) != nil || !releaseTag.MatchString(release.Tag) {
			return nil, errors.New("update_metadata_invalid")
		}
		ahead := false
		if current != release.Tag {
			comparison, err := b.Download(ctx, "https://api.github.com/repos/bol-van/zapret2/compare/"+current+"..."+release.Tag, 2<<20, cfg, emit)
			if err != nil {
				return nil, err
			}
			var compared struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(comparison, &compared) != nil {
				return nil, errors.New("update_comparison_invalid")
			}
			ahead = compared.Status == "ahead"
		}
		cached = updateCache{When: time.Now().UTC(), Current: current, Ahead: ahead, Release: release}
		if err = storage.Write(filepath.Join(b.State, "update-check.json"), cached); err != nil {
			return nil, err
		}
	}
	if !cached.Ahead {
		return result, nil
	}
	result["available"] = cached.Release.Tag
	if !cfg.Settings.AutoUpdateZapret {
		return result, nil
	}
	var reference runtimeReference
	if storage.Read(filepath.Join(b.State, "runtime-pending.json"), &reference) == nil && runtimeDirectory.MatchString(reference.Directory) {
		if pending, err := LoadRuntime(filepath.Join(b.runtimeUpdatesDir(), reference.Directory)); err == nil && pending.Manifest.Versions["zapret2"] == cached.Release.Tag {
			result["pending"] = true
			return result, nil
		}
	}
	var asset *updateAsset
	for _, candidate := range cached.Release.Assets {
		if candidate.Name == "zapret2-"+cached.Release.Tag+".tar.gz" {
			copy := candidate
			asset = &copy
			break
		}
	}
	if asset == nil || asset.Size < 1 || asset.Size > 64<<20 || !strings.HasPrefix(asset.Digest, "sha256:") || len(asset.Digest) != 71 || !strings.HasPrefix(asset.URL, "https://github.com/bol-van/zapret2/releases/download/"+cached.Release.Tag+"/") {
		return nil, errors.New("update_asset_unverified")
	}
	data, err := b.Download(ctx, asset.URL, asset.Size, cfg, emit)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != asset.Size || !verifyDigest(data, strings.TrimPrefix(asset.Digest, "sha256:")) {
		return nil, errors.New("update_digest_mismatch")
	}
	pending, err := b.stageUpdate(ctx, r, data, cached.Release.Tag)
	if err != nil {
		return nil, err
	}
	reference = runtimeReference{Directory: filepath.Base(pending.Dir), Base: b.bundledFingerprint}
	if err = storage.Write(filepath.Join(b.State, "runtime-pending.json"), reference); err != nil {
		return nil, err
	}
	result["pending"] = true
	return result, nil
}
func extractUpdate(archive []byte) (map[string][]byte, error) {
	selected := map[string]string{"binaries/linux-x86_64/nfqws2": "nfqws2", "lua/zapret-lib.lua": "lua/zapret-lib.lua", "lua/zapret-antidpi.lua": "lua/zapret-antidpi.lua", "docs/LICENSE.txt": "licenses/zapret2.txt"}
	blobs := map[string]string{"quic_initial_www_google_com.bin": "quic_google", "quic_initial_vk_com.bin": "quic_vk", "tls_clienthello_www_google_com.bin": "tls_google", "tls_clienthello_vk_com.bin": "tls_vk", "tls_clienthello_gosuslugi_ru.bin": "tls_gosuslugi", "stun.bin": "stun"}
	for original, name := range blobs {
		selected["files/fake/"+original] = "blobs/" + name + ".bin"
	}
	compressed, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, errors.New("update_archive_invalid")
	}
	defer compressed.Close()
	reader := tar.NewReader(io.LimitReader(compressed, 128<<20))
	files := map[string][]byte{}
	entries := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("update_archive_invalid")
		}
		entries++
		if entries > 20000 {
			return nil, errors.New("update_archive_invalid")
		}
		clean := path.Clean(header.Name)
		if path.IsAbs(clean) || strings.HasPrefix(clean, "../") || strings.Contains(clean, "\\") {
			return nil, errors.New("update_archive_invalid")
		}
		_, member, ok := strings.Cut(clean, "/")
		if !ok {
			continue
		}
		destination, wanted := selected[member]
		if !wanted {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > 32<<20 {
			return nil, errors.New("update_archive_invalid")
		}
		if _, exists := files[destination]; exists {
			return nil, errors.New("update_archive_duplicate")
		}
		data, err := boundedRead(reader, header.Size)
		if err != nil || int64(len(data)) != header.Size {
			return nil, errors.New("update_archive_invalid")
		}
		files[destination] = data
	}
	for _, required := range []string{"nfqws2", "lua/zapret-lib.lua", "lua/zapret-antidpi.lua"} {
		if len(files[required]) == 0 {
			return nil, errors.New("update_archive_incomplete")
		}
	}
	return files, nil
}
func (b *Backend) stageUpdate(ctx context.Context, base *Runtime, archive []byte, version string) (*Runtime, error) {
	files, err := extractUpdate(archive)
	if err != nil {
		return nil, err
	}
	directory := b.runtimeUpdatesDir()
	if err = os.MkdirAll(directory, 0755); err != nil {
		return nil, err
	}
	if err = trustedPath(directory, true); err != nil {
		return nil, err
	}
	if err = os.Chmod(directory, 0755); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(archive)
	name := "zapret_" + hex.EncodeToString(digest[:8])
	target := filepath.Join(directory, name)
	if cached, err := LoadRuntime(target); err == nil && cached.Manifest.Versions["zapret2"] == version {
		return cached, nil
	}
	stage, err := os.MkdirTemp(directory, ".stage-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	if err = os.Chmod(stage, 0755); err != nil {
		return nil, err
	}
	manifest := Manifest{Schema: 1, Versions: map[string]string{}, Files: map[string]string{}}
	for key, value := range base.Manifest.Versions {
		manifest.Versions[key] = value
	}
	manifest.Versions["zapret2"] = version
	for name := range base.Manifest.Files {
		data, ok := files[name]
		if !ok {
			data, err = os.ReadFile(base.Path(name))
			if err != nil {
				return nil, err
			}
		}
		destination := filepath.Join(stage, name)
		if err = os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			return nil, err
		}
		for parent := filepath.Dir(destination); parent != filepath.Dir(stage); parent = filepath.Dir(parent) {
			if err = os.Chmod(parent, 0755); err != nil {
				return nil, err
			}
		}
		mode := os.FileMode(0644)
		if name == "nfqws2" || name == "sing-box" || name == "xray" {
			mode = 0755
		}
		if err = os.WriteFile(destination, data, mode); err != nil {
			return nil, err
		}
		if err = os.Chmod(destination, mode); err != nil {
			return nil, err
		}
		hash := sha256.Sum256(data)
		manifest.Files[name] = hex.EncodeToString(hash[:])
	}
	if err = storage.Write(filepath.Join(stage, "integrity.json"), manifest); err != nil {
		return nil, err
	}
	runtime, err := LoadRuntime(stage)
	if err != nil {
		return nil, err
	}
	if err = validateUpdatedNfq(ctx, runtime); err != nil {
		return nil, err
	}
	if err = os.Rename(stage, target); err != nil {
		return nil, err
	}
	return LoadRuntime(target)
}
func validateUpdatedNfq(ctx context.Context, r *Runtime) error {
	base := []string{"--intercept=0", "--qnum=22700", "--lua-init=@" + r.Path("lua/zapret-lib.lua"), "--lua-init=@" + r.Path("lua/zapret-antidpi.lua"), "--lua-init=@" + r.Path("lua/zarp-observe.lua")}
	for _, blob := range []string{"quic_google", "quic_vk", "tls_google", "tls_vk", "tls_gosuslugi", "stun"} {
		base = append(base, "--blob="+blob+":@"+r.Path("blobs/"+blob+".bin"))
	}
	for _, strategy := range core.Catalog() {
		args := append(append([]string{}, base...), strategy.Args...)
		if os.Geteuid() != 0 {
			args = append([]string{"--dry-run"}, args...)
		}
		if _, err := Run(ctx, r.Path("nfqws2"), nil, args...); err != nil {
			return errors.New("updated_nfq_incompatible")
		}
	}
	return nil
}
func (b *Backend) activatePending() error {
	var reference runtimeReference
	if err := storage.Read(filepath.Join(b.State, "runtime-pending.json"), &reference); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if !runtimeDirectory.MatchString(reference.Directory) || reference.Base != b.bundledFingerprint {
		return errors.New("runtime_update_reference_invalid")
	}
	r, err := LoadRuntime(filepath.Join(b.runtimeUpdatesDir(), reference.Directory))
	if err != nil {
		return err
	}
	if err = storage.Write(filepath.Join(b.State, "runtime-active.json"), reference); err != nil {
		return err
	}
	b.mu.Lock()
	b.Runtime = r
	b.mu.Unlock()
	return os.Remove(filepath.Join(b.State, "runtime-pending.json"))
}
