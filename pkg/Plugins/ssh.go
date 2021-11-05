package Plugins

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/redtoolskobe/scaninfo/global"
	"go.uber.org/zap"

	"github.com/redtoolskobe/scaninfo/model"

	"github.com/redtoolskobe/scaninfo/pkg/common"
	"github.com/redtoolskobe/scaninfo/pkg/options"
	"golang.org/x/crypto/ssh"
)

func SshScan(info *options.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	for _, user := range info.Userdict["ssh"] {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := SshConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] ssh %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(info.Userdict["ssh"])*len(info.Passwords)) * info.Timeout) {
					return err
				}
			}
			if info.SshKey != "" {
				return err
			}
		}
	}
	return tmperr
}

func SshConn(info *options.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	Auth := []ssh.AuthMethod{}
	if info.SshKey != "" {
		pemBytes, err := ioutil.ReadFile(info.SshKey)
		if err != nil {
			return false, errors.New("read key failed" + err.Error())
		}
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return false, errors.New("parse key failed" + err.Error())
		}
		Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		Auth = []ssh.AuthMethod{ssh.Password(Password)}
	}

	config := &ssh.ClientConfig{
		User:    Username,
		Auth:    Auth,
		Timeout: time.Duration(info.Timeout) * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", Host, Port), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		if err == nil {
			defer session.Close()
			flag = true
			var result string
			if info.Command != "" {
				combo, _ := session.CombinedOutput(info.Command)
				result = fmt.Sprintf("[+] SSH:%v:%v:%v %v \n %v", Host, Port, Username, Password, string(combo))
				if info.SshKey != "" {
					result = fmt.Sprintf("[+] SSH:%v:%v sshkey correct \n %v", Host, Port, string(combo))
				}
				res := common.VulInfo{"weak_passwd", info.TaskID, map[string]interface{}{"weak_passwd": model.WeakPasswd{Type: "ssh", Result: result, Host: info.Host, Passwd: pass, Username: user}}}
				common.LogSuccess(&res)
			} else {
				result = fmt.Sprintf("[+] SSH:%v:%v:%v %v", Host, Port, Username, Password)
				if info.SshKey != "" {
					result = fmt.Sprintf("[+] SSH:%v:%v sshkey correct", Host, Port)
				}
				res := common.VulInfo{"weak_passwd", info.TaskID, map[string]interface{}{"weak_passwd": model.WeakPasswd{Type: "ssh", Result: result, Host: info.Host, Passwd: pass, Username: user}}}
				common.LogSuccess(&res)
				global.Log.Warn("weak_passwd", zap.String("ssh", "ssh"), zap.String("host", info.Host),
					zap.String("password", pass), zap.String("username", Username))
				model.WeakPasswdList = append(model.WeakPasswdList, model.WeakPasswd{"ssh", result, info.Host, info.Ports, pass, user})
			}
		}
	}
	return flag, err

}
