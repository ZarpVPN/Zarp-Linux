package linux

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func archiveFixture(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(compressed)
	for name, data := range files {
		if err := writer.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0644}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	writer.Close()
	compressed.Close()
	return buffer.Bytes()
}
func TestUpdateArchiveOnlyAcceptsKnownFiles(t *testing.T) {
	files := map[string][]byte{"release/binaries/linux-x86_64/nfqws2": []byte("binary"), "release/lua/zapret-lib.lua": []byte("lib"), "release/lua/zapret-antidpi.lua": []byte("dpi"), "release/unrelated-program": []byte("never extracted")}
	selected, err := extractUpdate(archiveFixture(t, files))
	if err != nil || len(selected) != 3 {
		t.Fatal(selected, err)
	}
	files["../../outside"] = []byte("escape")
	if _, err = extractUpdate(archiveFixture(t, files)); err == nil {
		t.Fatal("traversal accepted")
	}
	if _, err = extractUpdate(archiveFixture(t, map[string][]byte{"release/unknown": []byte("x")})); err == nil {
		t.Fatal("incomplete runtime accepted")
	}
}
func TestOfficialUpdateCanBeStagedWithoutReplacingTheBundledRuntime(t *testing.T) {
	fixture := os.Getenv("ZARP_TEST_UPDATE_ARCHIVE")
	if fixture == "" {
		t.Skip("set ZARP_TEST_UPDATE_ARCHIVE to the verified v1.0.6 archive")
	}
	archive, err := os.ReadFile(fixture)
	if os.IsNotExist(err) {
		t.Skip("optional verified release snapshot")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !verifyDigest(archive, "eb412aebc82cdef1f09b6aa9df45c8ff60fb88683b6663e6c4a9275d87ea2db4") {
		t.Fatal("release snapshot changed")
	}
	r, err := LoadRuntime(runtimeRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	state, err := os.MkdirTemp("", "zarp-update-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state); os.RemoveAll(state + "-runtime") })
	previousMask := syscall.Umask(0077)
	defer syscall.Umask(previousMask)
	b := NewBackend(r, state)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	staged, err := b.stageUpdate(ctx, r, archive, "v1.0.6")
	if err != nil {
		t.Fatal(err)
	}
	if b.Runtime != r {
		t.Fatal("running runtime was replaced while staging")
	}
	ref := runtimeReference{Directory: filepath.Base(staged.Dir), Base: r.Fingerprint}
	if err = storage.Write(filepath.Join(state, "runtime-pending.json"), ref); err != nil {
		t.Fatal(err)
	}
	if err = b.activatePending(); err != nil {
		t.Fatal(err)
	}
	if b.Runtime.Manifest.Versions["zapret2"] != "v1.0.6" {
		t.Fatal("pending update not activated")
	}
	restored := NewBackend(r, state)
	if restored.Runtime.Fingerprint != b.Runtime.Fingerprint {
		t.Fatal("validated update not restored")
	}
}
