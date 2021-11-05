package report

import (
	"fmt"
	"strconv"

	"github.com/redtoolskobe/scaninfo/model"

	"github.com/redtoolskobe/scaninfo/pkg/output"
	"github.com/xuri/excelize/v2"
)

func IcmpReport(filename string, iplist []string) {
	categories := map[string]string{
		"A1": "IP地址"}
	f := excelize.NewFile()
	index := f.NewSheet("IP地址")
	for k, v := range categories {
		f.SetCellValue("IP地址", k, v)
	}
	f.SetActiveSheet(index)
	for k, info := range iplist {
		f.SetSheetRow("IP地址", fmt.Sprint("A", k+2), &[]string{info})
	}
	// Save spreadsheet by the given path.
	if err := f.SaveAs(filename); err != nil {
		fmt.Println(err)
	}
}

func Port(filename string, portlist []*output.ResultEvent) {
	categories := map[string]string{
		"A1": "IP地址", "B1": "端口", "C1": "服务", "D1": "banner", "E1": "Url", "F1": "证书"}
	f, err := excelize.OpenFile(filename)
	if err != nil {
		fmt.Println("打开错误")
		return
	}
	index := f.NewSheet("端口服务")
	for k, v := range categories {
		f.SetCellValue("端口服务", k, v)
	}
	f.SetActiveSheet(index)
	for k, info := range portlist {
		f.SetSheetRow("端口服务", fmt.Sprint("A", k+2), &[]string{info.Ip, strconv.FormatUint(info.Port, 10),
			info.Info.Service, info.Info.Banner, info.Info.Url, info.Info.Cert})
	}
	// Save spreadsheet by the given path.
	if err := f.SaveAs(filename); err != nil {
		fmt.Println(err)
	}
}

func WebFingerReport(filename string, webfingerlist []model.WebFinger) {
	categories := map[string]string{
		"A1": "web地址", "B1": "状态码", "C1": "头部信息", "D1": "返回长度", "E1": "标题", "F1": "关键字指纹", "G1": "Hash指纹"}
	f, err := excelize.OpenFile(filename)
	if err != nil {
		fmt.Println("打开错误")
		return
	}
	index := f.NewSheet("web指纹")
	for k, v := range categories {
		f.SetCellValue("web指纹", k, v)
	}
	f.SetActiveSheet(index)
	for k, info := range webfingerlist {
		f.SetSheetRow("web指纹", fmt.Sprint("A", k+2), &[]string{info.Websitle, strconv.Itoa(info.StatusCode),
			info.HeaderDigest, strconv.Itoa(info.Length), info.Title, info.KeywordFinger, info.HashFinger})
	}
	// Save spreadsheet by the given path.
	if err := f.SaveAs(filename); err != nil {
		fmt.Println(err)
	}
}
func PluginReport(filename string, plugin []model.Plugin) {
	categories := map[string]string{
		"A1": "IP地址", "B1": "端口", "C1": "类型", "D1": "结果"}
	f, err := excelize.OpenFile(filename)
	if err != nil {
		fmt.Println("打开错误")
		return
	}
	index := f.NewSheet("插件漏洞")
	for k, v := range categories {
		f.SetCellValue("插件漏洞", k, v)
	}
	f.SetActiveSheet(index)
	for k, info := range plugin {
		f.SetSheetRow("插件漏洞", fmt.Sprint("A", k+2), &[]string{info.Host, info.Port,
			info.Type, info.Result})
	}
	// Save spreadsheet by the given path.
	if err := f.SaveAs(filename); err != nil {
		fmt.Println(err)
	}
}
func WeakPasswordReport(filename string, weakpass []model.WeakPasswd) {
	categories := map[string]string{
		"A1": "IP地址", "B1": "端口", "C1": "类型", "D1": "账号", "E1": "密码", "F1": "结果"}
	f, err := excelize.OpenFile(filename)
	if err != nil {
		fmt.Println("打开错误")
		return
	}
	index := f.NewSheet("弱口令")
	for k, v := range categories {
		f.SetCellValue("弱口令", k, v)
	}
	f.SetActiveSheet(index)
	for k, info := range weakpass {
		f.SetSheetRow("弱口令", fmt.Sprint("A", k+2), &[]string{info.Host, info.Port,
			info.Type, info.Username, info.Passwd, info.Result})
	}
	// Save spreadsheet by the given path.
	if err := f.SaveAs(filename); err != nil {
		fmt.Println(err)
	}
}
