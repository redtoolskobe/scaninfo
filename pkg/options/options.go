package options

import (
	"github.com/redtoolskobe/scaninfo/model"
	"github.com/redtoolskobe/scaninfo/pkg/common"
	"github.com/redtoolskobe/scaninfo/pkg/output"
)

type HostInfo struct {
	Host      string
	Ports     string
	Domain    string
	Url       string
	Path      string
	Timeout   int64
	Scantype  string
	Command   string
	SshKey    string
	Username  string
	Password  string
	Usernames []string
	Passwords []string
	Infostr   []string
	Hash      string
	Hosts     []string
	TaskName  string
	TaskID    string
	Userdict  map[string][]string
	TaskTotal []string
	TaskDown  []string
	TaskRun   []string
	Keyword   *[]model.Fingers
	Favicons  *[]model.Fingers
	ScanType  string
}

type ScanVul struct {
	Info            HostInfo
	ServicePortList []*output.ResultEvent
	UrlList         []string
}

func NewDefaultScanVul(urllist []string) *ScanVul {
	return &ScanVul{
		Info: HostInfo{
			Timeout:   3,
			Userdict:  common.Userdict,
			Passwords: common.Passwords,
		},
		UrlList: urllist,
	}
}
