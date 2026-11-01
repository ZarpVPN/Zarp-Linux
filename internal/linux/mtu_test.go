package linux

import "testing"

func TestWarpMSSFitsPhysicalLinkWithoutReducingNormalLinks(t *testing.T) {
	for mtu := 1280; mtu <= 1500; mtu++ {
		mss, err := warpMSSForMTU(mtu)
		if err != nil {
			t.Fatal(mtu, err)
		}
		if mss != 0 && (int(mss)+60+128 > mtu || mss < 512 || mss > 1220) {
			t.Fatal("encapsulated TCP segment would exceed physical link", mtu, mss)
		}
		if mtu == 1500 && mss != 0 {
			t.Fatal("ordinary Ethernet should retain native MSS")
		}
	}
	for _, mtu := range []int{0, 576, 1279, 65536} {
		if _, err := warpMSSForMTU(mtu); err == nil {
			t.Fatal("invalid MTU accepted", mtu)
		}
	}
}
