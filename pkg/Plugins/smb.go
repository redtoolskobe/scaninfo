package Plugins

import (
	"fmt"
	"strings"
	"time"

	"github.com/redtoolskobe/scaninfo/global"
	"go.uber.org/zap"

	"github.com/redtoolskobe/scaninfo/model"

	"github.com/redtoolskobe/scaninfo/pkg/options"

	"github.com/redtoolskobe/scaninfo/pkg/common"
	"github.com/stacktitan/smb/smb"
)

func SmbScan(info *options.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	for _, user := range info.Userdict["smb"] {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := doWithTimeOut(info, user, pass)
			if flag == true && err == nil {
				var result string
				if info.Domain != "" {
					result = fmt.Sprintf("[+] SMB:%v:%v:%v\\%v %v", info.Host, info.Ports, info.Domain, user, pass)
				} else {
					result = fmt.Sprintf("[+] SMB:%v:%v:%v %v", info.Host, info.Ports, user, pass)
				}
				res := common.VulInfo{"weak_passwd", info.TaskID, map[string]interface{}{"weak_passwd": model.WeakPasswd{Type: "smb", Result: result, Host: info.Host, Passwd: pass, Username: user}}}
				common.LogSuccess(&res)
				global.Log.Warn("weak_passwd", zap.String("smb", "smb"), zap.String("host", info.Host),
					zap.String("password", pass), zap.String("username", user))
				return err
			} else {
				errlog := fmt.Sprintf("[-] smb %v:%v %v %v %v", info.Host, 445, user, pass, err)
				errlog = strings.Replace(errlog, "\n", "", -1)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(info.Userdict["smb"])*len(info.Passwords)) * info.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func SmblConn(info *options.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	flag = false
	Host, Username, Password := info.Host, user, pass
	options := smb.Options{
		Host:        Host,
		Port:        445,
		User:        Username,
		Password:    Password,
		Domain:      info.Domain,
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			flag = true
		}
	}
	signal <- struct{}{}
	return flag, err
}

func doWithTimeOut(info *options.HostInfo, user string, pass string) (flag bool, err error) {
	signal := make(chan struct{})
	go func() {
		flag, err = SmblConn(info, user, pass, signal)
	}()
	select {
	case <-signal:
		return flag, err
	case <-time.After(time.Duration(info.Timeout) * time.Second):
		return false, err
	}
}
