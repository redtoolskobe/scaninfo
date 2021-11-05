package Plugins

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/redtoolskobe/scaninfo/global"
	"go.uber.org/zap"

	"github.com/redtoolskobe/scaninfo/model"

	_ "github.com/go-sql-driver/mysql"
	"github.com/redtoolskobe/scaninfo/pkg/common"
	"github.com/redtoolskobe/scaninfo/pkg/options"
)

func MysqlScan(info *options.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	for _, user := range info.Userdict["mysql"] {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := MysqlConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] mysql %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(info.Userdict["mysql"])*len(info.Passwords)) * info.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func MysqlConn(info *options.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", Username, Password, Host, Port, time.Duration(info.Timeout)*time.Second)
	db, err := sql.Open("mysql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout) * time.Second)
		//db.SetConnMaxIdleTime(time.Duration(info.Timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] mysql:%v:%v:%v %v", Host, Port, Username, Password)
			res := common.VulInfo{"weak_passwd", info.TaskID, map[string]interface{}{"weak_passwd": model.WeakPasswd{Type: "mysql", Result: result, Host: info.Host, Passwd: pass, Username: user}}}
			common.LogSuccess(&res)
			global.Log.Warn("weak_passwd", zap.String("mysql", "mysql"), zap.String("host", info.Host),
				zap.String("password", pass), zap.String("username", user))
			model.WeakPasswdList = append(model.WeakPasswdList, model.WeakPasswd{"mysql", result, info.Host, info.Ports, pass, user})
			flag = true
		}
	}
	return flag, err
}
