package model

import "github.com/redtoolskobe/scaninfo/pkg/output"

type WebFinger struct {
	HashFinger    string
	KeywordFinger string
	StatusCode    int
	Title         string
	Websitle      string
	HeaderDigest  string
	Length        int
}

type WeakPasswd struct {
	Type     string
	Result   string
	Host     string
	Port     string
	Passwd   string
	Username string
}

type Plugin struct {
	Type   string
	Result string
	Host   string
	Port   string
}

type ReportResult struct {
	PingList       []string
	PortList       []*output.ResultEvent
	FingerList     []WebFinger
	WeakPasswdList []WeakPasswd
	PluginList     []Plugin
}

var ResultReport ReportResult

var WeakPasswdList []WeakPasswd

var PluginList []Plugin

var WebFingerList []WebFinger
