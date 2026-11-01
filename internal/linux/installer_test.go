package linux

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestRepositoryDateAndSignedIndexBounds(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	if err := releaseFresh([]byte("Date: Tue, 20 Oct 2026 13:45:39 +0000\n"), now); err != nil {
		t.Fatal(err)
	}
	for _, date := range []string{"Date: Tue, 20 Jan 2026 13:45:39 +0000\n", "Date: Tue, 20 Oct 2027 13:45:39 +0000\n", "Date: Tue, 20 Oct 2026 13:45:39 +0000\nValid-Until: Tue, 21 Oct 2026 13:45:39 +0000\n", ""} {
		if releaseFresh([]byte(date), now) == nil {
			t.Fatal("replayed, expired or invalid metadata accepted")
		}
	}
	data := []byte("SHA256:\n " + strings.Repeat("a", 64) + " 128 main/binary-amd64/Packages.gz\n")
	record, err := releaseIndex(data, "main/binary-amd64/Packages.gz")
	if err != nil || record.Size != 128 {
		t.Fatal("signed hash section not parsed")
	}
}
func TestPackageMetadataCannotSelectAnotherProgramOrPath(t *testing.T) {
	valid := "Package: cloudflare-warp\nArchitecture: amd64\nVersion: 2026.8.1\nFilename: pool/main/c/cloudflare-warp/warp.deb\nSize: 2048\nSHA256: " + strings.Repeat("a", 64) + "\n"
	if packages, err := packageIndex([]byte(valid), "amd64"); err != nil || len(packages) != 1 {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(valid, "pool/main/c/cloudflare-warp/warp.deb", "../malicious.deb", 1), strings.Replace(valid, "Package: cloudflare-warp", "Package: unrelated", 1), strings.Replace(valid, "Size: 2048", "Size: 999999999999", 1)} {
		if _, err := packageIndex([]byte(bad), "amd64"); err == nil {
			t.Fatal("unsafe package metadata accepted")
		}
	}
}
func TestVerifiedOfficialRepositorySnapshot(t *testing.T) {
	work := os.Getenv("ZARP_TEST_WARP_FIXTURE")
	if work == "" {
		t.Skip("set ZARP_TEST_WARP_FIXTURE to a verified repository snapshot")
	}
	release, err := os.ReadFile(work + "/Release")
	if err != nil {
		t.Skip("optional verified official snapshot not present")
	}
	if err = releaseFresh(release, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = releaseIndex(release, "main/binary-amd64/Packages.gz"); err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile(work + "/Packages")
	if err != nil {
		t.Skip("package index snapshot not retained")
	}
	packages, err := packageIndex(index, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(work + "/warp.deb")
	if err != nil {
		t.Skip("official package snapshot not retained")
	}
	for _, p := range packages {
		if int64(len(data)) == p.File.Size && verifyDigest(data, p.File.SHA256) {
			return
		}
	}
	t.Fatal("verified package does not match the repository metadata parser")
}
