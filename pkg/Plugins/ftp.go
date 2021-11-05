package Plugins

import (
	"fmt"
	"strings"
	"time"

	"github.com/redtoolskobe/scaninfo/global"
	"go.uber.org/zap"

	"github.com/redtoolskobe/scaninfo/model"

	"github.com/jlaffaye/ftp"
	"github.com/redtoolskobe/scaninfo/pkg/common"
	"github.com/redtoolskobe/scaninfo/pkg/options"
)

func FtpScan(info *options.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	flag, err := FtpConn(info, "anonymous", "")
	if flag == true && err == nil {
		return err
	} else {
		errlog := fmt.Sprintf("[-] ftp://%v:%v %v %v", info.Host, info.Ports, "anonymous", err)
		common.LogError(errlog)
		tmperr = err
		if common.CheckErrs(err) {
			return err
		}
	}

	for _, user := range info.Userdict["ftp"] {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := FtpConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] ftp://%v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(info.Userdict["ftp"])*len(info.Passwords)) * info.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func FtpConn(info *options.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(info.Timeout)*time.Second)
	if err == nil {
		err = conn.Login(Username, Password)
		if err == nil {
			flag = true
			result := fmt.Sprintf("[+] ftp://%v:%v:%v %v", Host, Port, Username, Password)
			dirs, err := conn.List("")
			//defer conn.Logout()
			if err == nil {
				if len(dirs) > 0 {
					for i := 0; i < len(dirs); i++ {
						if len(dirs[i].Name) > 50 {
							result += "\n   [->]" + dirs[i].Name[:50]
						} else {
							result += "\n   [->]" + dirs[i].Name
						}
						if i == 5 {
							break
						}
					}
				}
			}
			res := common.VulInfo{"weak_passwd", info.TaskID, map[string]interface{}{"weak_passwd": model.WeakPasswd{Type: "ftp", Result: result, Host: info.Host, Passwd: pass, Username: user}}}
			common.LogSuccess(&res)
			global.Log.Warn("weak_passwd", zap.String("ftp", "ftp"), zap.String("host", info.Host),
				zap.String("password", pass), zap.String("username", user))
			model.WeakPasswdList = append(model.WeakPasswdList, model.WeakPasswd{"ftp", result, info.Host, info.Ports, pass, user})
		}
	}
	return flag, err
}
