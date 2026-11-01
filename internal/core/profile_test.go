package core

import (
	"encoding/base64"
	"strings"
	"testing"
)

const vlessTest = "vless://7822b3d8-506a-401e-992c-2784c932ead0@example.com:443?security=tls&sni=example.com&type=ws&path=%2Fedge#Example"

func TestProfileIdentityAndOuterTransport(t *testing.T) {
	p, err := ParseProfile(vlessTest)
	if err != nil {
		t.Fatal(err)
	}
	if p.Outer() != TLS || p.Path != "/edge" || p.Credential != "7822b3d8-506a-401e-992c-2784c932ead0" {
		t.Fatal("profile fields lost")
	}
	changed, err := ParseProfile(strings.Replace(vlessTest, "%2Fedge", "%2Fother", 1))
	if err != nil || changed.ID == p.ID {
		t.Fatal("configuration change must change server identity")
	}
	hy, err := ParseProfile("hy2://password@example.com:443?obfs=salamander&obfs-password=secret")
	if err != nil {
		t.Fatal(err)
	}
	if hy.Outer() != UDP {
		t.Fatal("obfuscated UDP must not be classified as a QUIC Initial")
	}
	if Compatible(Catalog()[0], &hy) {
		t.Fatal("QUIC-only strategy must not claim obfuscated UDP support")
	}
}
func TestRejectsUnprotectedOrAmbiguousProfiles(t *testing.T) {
	for _, link := range []string{
		"vless://7822b3d8-506a-401e-992c-2784c932ead0@example.com:443?security=none",
		strings.Replace(vlessTest, "security=tls", "security=tls&security=reality", 1),
		"trojan://secret@127.0.0.1:443",
		"trojan://secret@10.0.0.1:443",
		"trojan://secret@example.com:443?type=unknown",
		"vless://7822b3d8-506a-401e-992c-2784c932ead0@example.com:443?security=tls&type=xhttp&alpn=h3,h2",
		"vless://7822b3d8-506a-401e-992c-2784c932ead0@example.com:443?security=tls&type=xhttp&extra=%7B%22downloadSettings%22%3A%7B%22address%22%3A%22other.example%22%7D%7D",
		"trojan://secret@example.com:443?security=reality",
	} {
		if _, err := ParseProfile(link); err == nil {
			t.Fatalf("accepted unsafe profile: %s", strings.Split(link, "@xx")[0])
		}
	}
}
func TestSubscriptionLimitsAndOfflineFormat(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(vlessTest + "\nss://unsupported\n" + vlessTest))
	profiles, skipped, err := ParseSubscription([]byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || skipped != 1 {
		t.Fatal("subscription deduplication or unsupported count is wrong")
	}
	for _, body := range []string{"<html>blocked</html>", "{\"error\":true}", strings.Repeat("a", 2*1024*1024+1)} {
		if _, _, err = ParseSubscription([]byte(body)); err == nil {
			t.Fatal("invalid subscription accepted")
		}
	}
}
func TestCustomStrategiesCannotExecuteCode(t *testing.T) {
	for _, arg := range []string{"--lua-init=os.execute('id')", "--lua-desync=luaexec:code=os.execute('id')", "--lua-desync=fake:blob=@/etc/passwd", "--lua-desync=fake:blob=quic_google:repeats=1000", "--lua-desync=fake:fwmark=0", "--lua-desync=multisplit:pos=1;touch"} {
		text := "bad | h3 | --payload=quic_initial " + arg
		if _, err := ParseStrategies(text); err == nil {
			t.Fatalf("accepted privileged option %s", arg)
		}
	}
	for _, s := range Catalog() {
		if err := ValidateStrategy(s); err != nil {
			t.Fatalf("built-in %s: %v", s.ID, err)
		}
	}
	if _, err := ParseStrategies("plain | h3 | "); err == nil {
		t.Fatal("plain custom strategy accepted")
	}
}
