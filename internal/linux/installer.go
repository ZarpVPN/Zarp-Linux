package linux

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

type RepositoryFile struct {
	Path   string
	Size   int64
	SHA256 string
}
type DebianPackage struct {
	File    RepositoryFile
	Version string
}

var digestPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var suitePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

func releaseIndex(data []byte, wanted string) (RepositoryFile, error) {
	if len(data) > 1024*1024 {
		return RepositoryFile{}, errors.New("repository_release_too_large")
	}
	inHashes := false
	for _, line := range strings.Split(string(data), "\n") {
		if line == "SHA256:" {
			inHashes = true
			continue
		}
		if !strings.HasPrefix(line, " ") {
			inHashes = false
		}
		if inHashes {
			f := strings.Fields(line)
			if len(f) == 3 && f[2] == wanted {
				size, err := strconv.ParseInt(f[1], 10, 64)
				if err != nil || size < 1 || size > 20*1024*1024 || !digestPattern.MatchString(f[0]) {
					return RepositoryFile{}, errors.New("repository_index_invalid")
				}
				return RepositoryFile{Path: wanted, Size: size, SHA256: f[0]}, nil
			}
		}
	}
	return RepositoryFile{}, errors.New("repository_index_not_found")
}

func releaseFresh(data []byte, now time.Time) error {
	var date, until time.Time
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		if name == "Date" || name == "Valid-Until" {
			var parsed time.Time
			var err error
			for _, layout := range []string{time.RFC1123Z, time.RFC1123} {
				parsed, err = time.Parse(layout, value)
				if err == nil {
					break
				}
			}
			if err != nil {
				return errors.New("repository_release_date_invalid")
			}
			if name == "Date" {
				date = parsed
			} else {
				until = parsed
			}
		}
	}
	if date.IsZero() || date.After(now.Add(24*time.Hour)) || now.Sub(date) > 90*24*time.Hour || !until.IsZero() && now.After(until) {
		return errors.New("repository_release_expired_or_future")
	}
	return nil
}

func packageIndex(data []byte, arch string) ([]DebianPackage, error) {
	if len(data) > 20*1024*1024 {
		return nil, errors.New("repository_index_too_large")
	}
	var packages []DebianPackage
	for _, paragraph := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(paragraph, "\n") {
			k, v, ok := strings.Cut(line, ": ")
			if ok {
				fields[k] = v
			}
		}
		if fields["Package"] != "cloudflare-warp" || fields["Architecture"] != arch {
			continue
		}
		size, err := strconv.ParseInt(fields["Size"], 10, 64)
		file := fields["Filename"]
		if err != nil || size < 1024 || size > 256*1024*1024 || !digestPattern.MatchString(fields["SHA256"]) || !strings.HasPrefix(file, "pool/") || path.Clean(file) != file || strings.ContainsAny(file, "?\\#\x00") || len(fields["Version"]) > 128 {
			return nil, errors.New("repository_package_invalid")
		}
		packages = append(packages, DebianPackage{File: RepositoryFile{Path: file, Size: size, SHA256: fields["SHA256"]}, Version: fields["Version"]})
	}
	if len(packages) == 0 {
		return nil, errors.New("warp_package_unavailable_for_platform")
	}
	return packages, nil
}

func distroSuite() (string, error) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", errors.New("linux_distribution_unknown")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			values[k] = strings.Trim(v, "\"")
		}
	}
	if values["ID"] != "ubuntu" && values["ID"] != "debian" && values["UBUNTU_CODENAME"] == "" {
		return "", errors.New("automatic_warp_install_requires_ubuntu_or_debian")
	}
	suite := values["VERSION_CODENAME"]
	if values["UBUNTU_CODENAME"] != "" {
		suite = values["UBUNTU_CODENAME"]
	}
	if !suitePattern.MatchString(suite) {
		return "", errors.New("linux_distribution_suite_unknown")
	}
	return suite, nil
}

func (b *Backend) installWarp(ctx context.Context, cfg core.Config, emit func(string)) error {
	if !cfg.Settings.AcceptedTerms {
		return errors.New("warp_terms_required")
	}
	suite, err := distroSuite()
	if err != nil {
		return err
	}
	if runtime.GOARCH != "amd64" {
		return errors.New("automatic_warp_install_architecture_unsupported")
	}
	gpgv, err := SystemPath("gpgv")
	if err != nil {
		return err
	}
	dpkg, err := SystemPath("dpkg")
	if err != nil {
		return err
	}
	apt, err := SystemPath("apt-get")
	if err != nil {
		return err
	}
	emit("warp_downloading_metadata")
	base := "https://pkg.cloudflareclient.com/"
	release, err := b.Download(ctx, base+"dists/"+suite+"/InRelease", 1024*1024, cfg, emit)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(b.State, "warp-install-")
	if err != nil {
		return errors.New("installer_storage_failed")
	}
	defer os.RemoveAll(dir)
	if err = os.WriteFile(dir+"/InRelease", release, 0600); err != nil {
		return err
	}
	if _, err = Run(ctx, gpgv, nil, "--homedir", dir, "--keyring", b.Runtime.Path("cloudflare-warp-keyring.gpg"), "--output", dir+"/Release", dir+"/InRelease"); err != nil {
		return errors.New("warp_repository_signature_invalid")
	}
	verified, err := os.ReadFile(dir + "/Release")
	if err != nil {
		return errors.New("repository_release_unavailable")
	}
	if err = releaseFresh(verified, time.Now()); err != nil {
		return err
	}
	index, err := releaseIndex(verified, "main/binary-amd64/Packages.gz")
	if err != nil {
		return err
	}
	compressed, err := b.Download(ctx, base+"dists/"+suite+"/"+index.Path, index.Size, cfg, emit)
	if err != nil {
		return err
	}
	if int64(len(compressed)) != index.Size || !verifyDigest(compressed, index.SHA256) {
		return errors.New("warp_repository_checksum_invalid")
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return errors.New("repository_index_invalid")
	}
	plain, err := io.ReadAll(io.LimitReader(reader, 20*1024*1024+1))
	reader.Close()
	if err != nil {
		return errors.New("repository_index_invalid")
	}
	packages, err := packageIndex(plain, "amd64")
	if err != nil {
		return err
	}
	selected := packages[0]
	for _, candidate := range packages[1:] {
		if _, e := Run(ctx, dpkg, nil, "--compare-versions", candidate.Version, "gt", selected.Version); e == nil {
			selected = candidate
		}
	}
	emit("warp_downloading_package")
	data, err := b.Download(ctx, base+selected.File.Path, selected.File.Size, cfg, emit)
	if err != nil {
		return err
	}
	if int64(len(data)) != selected.File.Size || !verifyDigest(data, selected.File.SHA256) {
		return errors.New("warp_package_integrity_failed")
	}
	if err = os.WriteFile(dir+"/cloudflare-warp.deb", data, 0600); err != nil {
		return errors.New("installer_storage_failed")
	}
	data = nil
	// Verify identity after the signed repository hash, before package installation.
	identity, err := Run(ctx, dpkg, nil, "--field", dir+"/cloudflare-warp.deb", "Package", "Architecture")
	if err != nil || !strings.Contains(identity, "cloudflare-warp") || !strings.Contains(identity, "amd64") {
		return errors.New("warp_package_identity_invalid")
	}
	emit("warp_installing")
	limit, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if _, err = Run(limit, apt, nil, "install", "-y", "--no-install-recommends", dir+"/cloudflare-warp.deb"); err != nil {
		return errors.New("warp_package_install_failed")
	}
	if _, err = SystemPath("warp-cli"); err != nil {
		return errors.New("warp_cli_missing_after_install")
	}
	return nil
}
