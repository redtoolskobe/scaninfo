package Plugins

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/redtoolskobe/scaninfo/model"

	"github.com/redtoolskobe/scaninfo/global"
	"go.uber.org/zap"

	"github.com/redtoolskobe/scaninfo/pkg/options"

	"github.com/redtoolskobe/scaninfo/pkg/common"
)

var (
	bufferV1, _ = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	bufferV2, _ = hex.DecodeString("050000031000000018000000010000000000000000000500")
	bufferV3, _ = hex.DecodeString("0900ffff0000")
)

func Findnet(info *options.HostInfo) error {
	err := FindnetScan(info)
	return err
}

func FindnetScan(info *options.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, 135)
	conn, err := net.DialTimeout("tcp", realhost, time.Duration(info.Timeout)*time.Second)
	if err != nil {
		return err
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(info.Timeout) * time.Second))
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(bufferV1)
	if err != nil {
		return err
	}
	reply := make([]byte, 4096)
	_, err = conn.Read(reply)
	if err != nil {
		return err
	}
	_, err = conn.Write(bufferV2)
	if err != nil {
		return err
	}
	if n, err := conn.Read(reply); err != nil || n < 42 {
		return err
	}
	text := reply[42:]
	flag := true
	for i := 0; i < len(text)-5; i++ {
		if bytes.Equal(text[i:i+6], bufferV3) {
			text = text[:i-4]
			flag = false
			break
		}
	}
	if flag {
		return err
	}
	err = read(text, info.Host, info)
	return err
}
func read(text []byte, host string, info *options.HostInfo) error {
	encodedStr := hex.EncodeToString(text)
	hostnames := strings.Replace(encodedStr, "0700", "", -1)
	hostname := strings.Split(hostnames, "000000")
	result := "NetInfo:\n[*]" + host
	for i := 0; i < len(hostname); i++ {
		hostname[i] = strings.Replace(hostname[i], "00", "", -1)
		host, err := hex.DecodeString(hostname[i])
		if err != nil {
			return err
		}
		result += "\n   [->]" + string(host)
	}
	res := common.VulInfo{"plugin", info.TaskID, map[string]interface{}{"type": "findnet", "result": result, "host": host}}
	common.LogSuccess(&res)
	global.Log.Warn("plugin", zap.String("findnet", "findnet"), zap.String("host", info.Host),
		zap.String("result", result))
	model.PluginList = append(model.PluginList, model.Plugin{"findnet", result, host, info.Ports})
	return nil
}
