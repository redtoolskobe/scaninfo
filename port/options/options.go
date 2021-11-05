package options

import "go.uber.org/ratelimit"

type Options struct {
	CmdIps []string
	// cmdExPath  string
	CmdCofPath string
	CmdPorts   []string
	CmdT1000   bool
	CmdRandom  bool
	NumThreads int
	ExcPorts   []string // 待排除端口
	ExcIps     []string // 待排除Ip
	IpFile     string
	Nocolor    bool //彩色打印
	Json       bool
	Tracelog   string  //请求日志
	Rstfile    string  //文件保存
	Tout       float64 //timeout
	Nbtscan    bool
	Limit      int
	Limiter    ratelimit.Limiter
}
