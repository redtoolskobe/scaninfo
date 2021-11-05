package common

import (
	"strings"
	"sync"
	"time"
)

var Results = make(chan *VulInfo)
var Start = true
var LogSucTime int64
var LogErrTime int64
var WaitTime int64
var Silent bool
var LogWG sync.WaitGroup
var VulList []*VulInfo

type VulInfo struct {
	Name   string
	TaskID string
	Result map[string]interface{}
}

func CheckErrs(err error) bool {
	if err == nil {
		return false
	}
	errs := []string{
		"closed by the remote host", "too many connections",
		"i/o timeout", "EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
		"ssh: handshake failed",
	}
	for _, key := range errs {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(key)) {
			return true
		}
	}
	return false
}

func init() {
	go SaveLog()
}

func LogSuccess(result *VulInfo) {
	LogWG.Add(1)
	LogSucTime = time.Now().Unix()
	Results <- result
}

func SaveLog() {
	for result := range Results {
		VulList = append(VulList, result)
		//TaskResult := model.TaskResult{TakId: result.TaskID, TaskType: "fscan", JsonVulInfo: utils.JsonToByte(result), ResultType: result.Name}
		//_ = db.SaveTaskResult(&TaskResult)
		LogWG.Done()
	}
}

func LogError(errinfo interface{}) {
	if WaitTime == 0 {
		//gologger.Info().Msgf("[FSCAN]-[error]]", errinfo)
	} else if (time.Now().Unix()-LogSucTime) > WaitTime && (time.Now().Unix()-LogErrTime) > WaitTime {
		//gologger.Info().Msgf("[FSCAN]-[error]]", errinfo)
		LogErrTime = time.Now().Unix()
	}
}
