package cmd

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redtoolskobe/scaninfo/utils"

	"github.com/pterm/pterm"

	"github.com/redtoolskobe/scaninfo/pkg/Plugins"

	"github.com/redtoolskobe/scaninfo/pkg/common"
	"github.com/redtoolskobe/scaninfo/pkg/options"
	"github.com/redtoolskobe/scaninfo/pkg/output"
)

type ScanEngine struct {
	ServiceList []string         //要扫描的服务列表
	ScanType    string           //扫描的服务类型
	Options     *options.ScanVul //扫描的一些选项
	Bar         *pterm.ProgressbarPrinter
	Writer      output.Writer
	Ticker      *time.Ticker
	ComCount    int64
}

func NewScanEngine(options *options.ScanVul) *ScanEngine {
	return &ScanEngine{
		ServiceList: common.ScanTypeList,
		Options:     options,
		ScanType:    common.ScanMethodMap[common.Method],
	}
}

func (s *ScanEngine) Scan() {
	var Count int64
	var ch = make(chan struct{}, common.WebVulThreds)
	var wg = sync.WaitGroup{}
	tasklist := GetTaskList(s.Options.ServicePortList, s.ScanType, s.Options.UrlList)
	if tasklist == nil {
		return
	}
	for _, v := range tasklist {
		atomic.AddInt64(&Count, (int64(len(v))))
	}
	pterm.NewRGB(15, 199, 209).Println("需要扫描的web指纹和漏洞数量为", Count)
	s.Bar, _ = pterm.DefaultProgressbar.WithTotal(int(Count)).WithTitle("[ScanInfo]").WithRemoveWhenDone(true).Start()
	for service, v := range tasklist {
		for _, info := range v {
			info.Userdict = s.Options.Info.Userdict
			info.Passwords = s.Options.Info.Passwords
			info.Timeout = s.Options.Info.Timeout
			s.AddScan(service, info, ch, &wg)
		}
	}

	wg.Wait()
	common.LogWG.Wait()
	s.Bar.Stop()
}

func (s *ScanEngine) AddScan(service string, info options.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		scanplugin(Plugins.PluginList, service, &info)
		wg.Done()
		<-ch
		s.Bar.Add(1)
	}()
	ch <- struct{}{}
}

func scanplugin(m map[string]interface{}, name string, infos ...interface{}) (result []reflect.Value, err error) {
	f := reflect.ValueOf(m[name])
	if len(infos) != f.Type().NumIn() {
		err = errors.New("The number of infos is not adapted ")
		//fmt.Println(err.Error())
		return result, nil
	}
	in := make([]reflect.Value, len(infos))
	for k, info := range infos {
		in[k] = reflect.ValueOf(info)
	}
	result = f.Call(in)
	return result, nil
}

func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func GetTaskList(servicelist []*output.ResultEvent, scantype string, urllist []string) map[string][]options.HostInfo {
	task := map[string][]options.HostInfo{}
	k, f, err := utils.GetFingerList(common.FingerFile)
	if err != nil {
		pterm.Warning.Println(fmt.Sprintf("指纹文件错误！已忽略web指纹扫描 %s", err.Error()))
	}
	for _, service := range servicelist {
		switch {
		case service.Port == 445:
			task["1000001"] = append(task["1000001"], options.HostInfo{Host: service.Ip, Ports: strconv.FormatUint(service.Port, 10)})
			task["1000002"] = append(task["1000002"], options.HostInfo{Host: service.Ip, Ports: strconv.FormatUint(service.Port, 10)})
			task["smb"] = append(task["smb"], options.HostInfo{Host: service.Ip, Ports: strconv.FormatUint(service.Port, 10)})
		case service.Port == 135:
			task["findnet"] = append(task["findnet"], options.HostInfo{Host: service.Ip, Ports: strconv.FormatUint(service.Port, 10)})
		case service.Port == 139:
			task["netbios"] = append(task["netbios"], options.HostInfo{Host: service.Ip, Ports: strconv.FormatUint(service.Port, 10)})
		case service.Info.Url != "" && err == nil:
			task["1000003"] = append(task["1000003"], options.HostInfo{Host: service.Ip, Ports: strconv.FormatUint(service.Port, 10), Url: service.Info.Url,
				Favicons: &f, Keyword: &k})
		case IsContain(common.ScanTypeList, service.Info.Service):
			task[service.Info.Service] = append(task[service.Info.Service], options.HostInfo{Host: service.Ip, Ports: strconv.FormatUint(service.Port, 10)})
		default:

		}
	}
	//url列表
	for _, url := range urllist {
		if err == nil {
			task["1000003"] = append(task["1000003"], options.HostInfo{Url: url, Favicons: &f, Keyword: &k})
		}
	}
	if scantype == "all" {
		return task
	} else {
		one := map[string][]options.HostInfo{}
		one[scantype] = task[scantype]
		return one
	}
}
