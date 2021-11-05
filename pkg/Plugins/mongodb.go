package Plugins

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/redtoolskobe/scaninfo/global"
	"go.uber.org/zap"

	"github.com/redtoolskobe/scaninfo/model"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/redtoolskobe/scaninfo/pkg/common"
	"github.com/redtoolskobe/scaninfo/pkg/options"
)

func MongodbScan(info *options.HostInfo) error {
	_, err := MongodbUnauth(info)
	if err != nil {
		errlog := fmt.Sprintf("[-] Mongodb %v:%v %v", info.Host, info.Ports, err)
		common.LogError(errlog)
	}
	return err
}

func MongodbUnauth(info *options.HostInfo) (flag bool, err error) {
	flag = false
	senddata := []byte{58, 0, 0, 0, 167, 65, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 255, 255, 255, 255, 19, 0, 0, 0, 16, 105, 115, 109, 97, 115, 116, 101, 114, 0, 1, 0, 0, 0, 0}
	getlogdata := []byte{72, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 1, 0, 0, 0, 33, 0, 0, 0, 2, 103, 101, 116, 76, 111, 103, 0, 16, 0, 0, 0, 115, 116, 97, 114, 116, 117, 112, 87, 97, 114, 110, 105, 110, 103, 115, 0, 0}
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := net.DialTimeout("tcp", realhost, time.Duration(info.Timeout)*time.Second)
	if err != nil {
		return flag, err
	}
	defer conn.Close()
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(info.Timeout) * time.Second))
	if err != nil {
		return flag, err
	}
	_, err = conn.Write(senddata)
	if err != nil {
		return flag, err
	}
	buf := make([]byte, 1024)
	count, err := conn.Read(buf)
	if err != nil {
		return flag, err
	}
	text := string(buf[0:count])
	if strings.Contains(text, "ismaster") {
		_, err = conn.Write(getlogdata)
		if err != nil {
			return flag, err
		}
		count, err := conn.Read(buf)
		if err != nil {
			return flag, err
		}
		text := string(buf[0:count])
		if strings.Contains(text, "totalLinesWritten") {
			flag = true
			result := fmt.Sprintf("[+] Mongodb:%v unauthorized", realhost)
			res := common.VulInfo{"weak_passwd", info.TaskID, map[string]interface{}{"weak_passwd": model.WeakPasswd{Type: "mongodb", Result: result, Host: info.Host, Passwd: "", Username: ""}}}
			common.LogSuccess(&res)
			global.Log.Warn("weak_passwd", zap.String("mongodb", "mongodb"), zap.String("host", info.Host),
				zap.String("password", ""), zap.String("username", ""))
			model.WeakPasswdList = append(model.WeakPasswdList, model.WeakPasswd{"mongodb", result, info.Host, info.Ports, "", ""})
		}
	}
	return flag, err
}
