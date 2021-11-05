package Plugins

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/redtoolskobe/scaninfo/global"
	"go.uber.org/zap"

	"github.com/redtoolskobe/scaninfo/model"

	_ "github.com/lib/pq"
	"github.com/redtoolskobe/scaninfo/pkg/common"
	"github.com/redtoolskobe/scaninfo/pkg/options"
)

func PostgresScan(info *options.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	for _, user := range info.Userdict["postgresql"] {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", string(user), -1)
			flag, err := PostgresConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] psql %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(info.Userdict["postgresql"])*len(info.Passwords)) * info.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func PostgresConn(info *options.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", Username, Password, Host, Port, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout) * time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("Postgres:%v:%v:%v %v", Host, Port, Username, Password)
			res := common.VulInfo{"weak_passwd", info.TaskID, map[string]interface{}{"weak_passwd": model.WeakPasswd{Type: "postgres", Result: result, Host: info.Host, Passwd: pass, Username: user}}}
			global.Log.Warn("weak_passwd", zap.String("postgres", "postgres"), zap.String("host", info.Host),
				zap.String("password", pass), zap.String("username", user))
			common.LogSuccess(&res)
			model.WeakPasswdList = append(model.WeakPasswdList, model.WeakPasswd{"postgres", result, info.Host, info.Ports, pass, user})
			flag = true
		}
	}
	return flag, err
}
