package Plugins

import (
	"github.com/redtoolskobe/scaninfo/global"
	"github.com/redtoolskobe/scaninfo/model"
	"github.com/redtoolskobe/scaninfo/pkg/options"
	"go.uber.org/zap"

	"github.com/redtoolskobe/scaninfo/finger"
	"github.com/redtoolskobe/scaninfo/pkg/common"
)

func WebTitle(info *options.HostInfo) error {
	Finger(info)
	return nil
}

//flag 1 first try
//flag 2 /favicon.ico
//flag 3 302
//flag 4 400 -> https

func Finger(info *options.HostInfo) {
	res := finger.Run(info.Url, info.Keyword, info.Favicons)
	result := model.WebFinger{HeaderDigest: res.HeaderDigest, Websitle: info.Url, Title: res.Title, Length: res.Length, StatusCode: res.StatusCode,
		KeywordFinger: res.KeywordFinger, HashFinger: res.HashFinger}
	common.LogSuccess(&common.VulInfo{"webtitle", info.TaskID, map[string]interface{}{"webtitle": result}})
	global.Log.Info("webtitle", zap.String("url", info.Url), zap.Int("StatusCode", res.StatusCode), zap.String("Title", res.Title), zap.String("HeaderDigest", res.HeaderDigest),
		zap.Int("Length", res.Length), zap.String("KeywordFinger", res.KeywordFinger), zap.String("HashFinger", res.HashFinger))
	model.WebFingerList = append(model.WebFingerList, result)
}
