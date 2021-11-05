package Plugins

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/redtoolskobe/scaninfo/global"
	"go.uber.org/zap"

	"github.com/redtoolskobe/scaninfo/model"

	"github.com/redtoolskobe/scaninfo/pkg/options"

	"github.com/redtoolskobe/scaninfo/pkg/common"
)

func RedisScan(info *options.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	flag, err := RedisUnauth(info)
	if flag == true && err == nil {
		return err
	}
	for _, pass := range info.Passwords {
		pass = strings.Replace(pass, "{user}", "redis", -1)
		flag, err := RedisConn(info, pass)
		if flag == true && err == nil {
			return err
		} else {
			errlog := fmt.Sprintf("[-] redis %v:%v %v %v", info.Host, info.Ports, pass, err)
			common.LogError(errlog)
			tmperr = err
			if common.CheckErrs(err) {
				return err
			}
			if time.Now().Unix()-starttime > (int64(len(info.Passwords)) * info.Timeout) {
				return err
			}
		}
	}
	return tmperr
}

func RedisConn(info *options.HostInfo, pass string) (flag bool, err error) {
	flag = false
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
	_, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", pass)))
	if err != nil {
		return flag, err
	}
	reply, err := readreply(conn)
	if err != nil {
		return flag, err
	}
	if strings.Contains(reply, "+OK") {
		result := fmt.Sprintf("[+] Redis:%s %s", realhost, pass)
		res := common.VulInfo{"weak_passwd", info.TaskID, map[string]interface{}{"weak_passwd": model.WeakPasswd{Type: "redis", Result: result, Host: info.Host, Passwd: pass, Username: ""}}}
		common.LogSuccess(&res)
		global.Log.Warn("weak_passwd", zap.String("redis", "redis"), zap.String("host", info.Host),
			zap.String("password", pass), zap.String("username", ""))
		model.WeakPasswdList = append(model.WeakPasswdList, model.WeakPasswd{"redis", result, info.Host, info.Ports, pass, ""})
		flag = true
	}
	return flag, err
}

func RedisUnauth(info *options.HostInfo) (flag bool, err error) {
	flag = false
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
	_, err = conn.Write([]byte("info\r\n"))
	if err != nil {
		return flag, err
	}
	reply, err := readreply(conn)
	if err != nil {
		return flag, err
	}
	if strings.Contains(reply, "redis_version") {
		result := fmt.Sprintf("[+] Redis:%s unauthorized", realhost)
		res := common.VulInfo{"weak_passwd", info.TaskID, map[string]interface{}{"weak_passwd": model.WeakPasswd{Type: "redis", Result: result, Host: info.Host, Passwd: "", Username: ""}}}
		global.Log.Warn("weak_passwd", zap.String("redis", "redis"), zap.String("host", info.Host),
			zap.String("password", ""), zap.String("username", ""))
		common.LogSuccess(&res)
		model.WeakPasswdList = append(model.WeakPasswdList, model.WeakPasswd{"redis", result, info.Host, info.Ports, "", ""})
	}
	return flag, err
}

func readreply(conn net.Conn) (result string, err error) {
	buf := make([]byte, 4096)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result += string(buf[0:count])
		if count < 4096 {
			break
		}
	}
	return result, err
}
