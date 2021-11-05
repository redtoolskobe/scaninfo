package common

import (
	"testing"
)

func TestComparePacketsMysql(t *testing.T) {
	banner := []byte(">\x00\x00\x00\x0a5.0.51a-3ubuntu5\x00\x0e\x00\x00\x00pf.Q.2Mn\x00,ª\x08\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c'4pXG<56Oh?\x00\x10\x00\x00\x01ÿ\x13\x04Bad handshake")

	size := len(banner)
	var szBan string
	var szSvcName string

	num := ComparePackets(banner, size, &szBan, &szSvcName)

	if num == 0 {
		t.Error("unknown service")
		return
	}

	t.Log(szBan)
	t.Log(szSvcName)
}
