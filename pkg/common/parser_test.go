package common

import "testing"

func TestConfigeFileParse(t *testing.T) {
	path := "D:\\gotest\\config.conf"

	ips, err := ConfigeFileParse(path)
	if err != nil {
		t.Log(err)
	}

	for _, line := range ips {
		t.Log(line)
	}
}
