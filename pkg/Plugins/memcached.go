package Plugins

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/redtoolskobe/scaninfo/global"
	"go.uber.org/zap"

	"github.com/redtoolskobe/scaninfo/model"

	"github.com/redtoolskobe/scaninfo/pkg/common"
	"github.com/redtoolskobe/scaninfo/pkg/options"
)

func MemcachedScan(info *options.HostInfo) (err error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	client, err := net.DialTimeout("tcp", realhost, time.Duration(info.Timeout)*time.Second)
	if err == nil {
		err = client.SetDeadline(time.Now().Add(time.Duration(info.Timeout) * time.Second))
		if err == nil {
			_, err = client.Write([]byte("stats\n")) //Set the key randomly to prevent the key on the server from being overwritten
			if err == nil {
				rev := make([]byte, 1024)
				n, err := client.Read(rev)
				if err == nil {
					if strings.Contains(string(rev[:n]), "STAT") {
						result := fmt.Sprintf("[+] Memcached %s unauthorized", realhost)
						res := common.VulInfo{"weak_passwd", info.TaskID, map[string]interface{}{"weak_passwd": model.WeakPasswd{Type: "memcached", Result: result, Host: info.Host, Passwd: "", Username: ""}}}
						common.LogSuccess(&res)
						global.Log.Warn("weak_passwd", zap.String("memcached", "mecached"), zap.String("host", info.Host),
							zap.String("password", ""), zap.String("username", ""))
						model.WeakPasswdList = append(model.WeakPasswdList, model.WeakPasswd{"memcached", result, info.Host, info.Ports, "", ""})
					}
					client.Close()
				} else {
					errlog := fmt.Sprintf("[-] Memcached %v:%v %v", info.Host, info.Ports, err)
					common.LogError(errlog)
				}
			}
		}
	}
	return err
}
