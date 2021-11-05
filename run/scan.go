package run

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/redtoolskobe/scaninfo/imcp"

	"github.com/redtoolskobe/scaninfo/utils"

	"github.com/redtoolskobe/scaninfo/pkg/common"

	"github.com/redtoolskobe/scaninfo/model"

	"github.com/redtoolskobe/scaninfo/pkg/output"

	"github.com/redtoolskobe/scaninfo/pkg/report"

	"github.com/redtoolskobe/scaninfo/pkg/options"

	"github.com/pterm/pterm"
	ps "github.com/redtoolskobe/scaninfo/pkg/common/ipparser"
	"github.com/redtoolskobe/scaninfo/port/runner"
	"github.com/redtoolskobe/scaninfo/scanvul/cmd"
)

func Start(ctx context.Context) {
	go Finderlist()
	option := common.NewDefaultOptions()
	engine := runner.CreateEngine(option)
	// 命令行参数错误
	if err := engine.Parser(); err != nil {
		fmt.Println(err)
	}
	//获得IP
	for _, ipnum := range engine.TaskIps {
		for ips := ipnum.Begin; ips <= ipnum.End; ips++ {
			ip := ps.UnParseIPv4(ips)
			engine.Options.IpList = append(engine.Options.IpList, ip)
		}
	}
	//判断端口扫描是否只针对icmp存活主机
	if common.Noping == false {
		engine.Options.IpList = imcp.ICMPRun(engine.Options.IpList, false)
	}
	report.IcmpReport(common.Rstfile+".xlsx", engine.Options.IpList)
	if common.Method == "ping" {
		return
	}
	engine.Ctx = ctx
	//端口扫描与服务识别
	pterm.Info.Println("正在进行端口探测... (请等待)")
	engine.Run()
	spinnerSuccess, _ := pterm.DefaultSpinner.Start("整理端口扫描结果")
	select {
	case <-ctx.Done():
		pterm.Success.Println("父线程已经退去")
	default:
		engine.Wg.Wait()
		if engine.Writer != nil {
		}
	}
	spinnerSuccess.Success()
	//engine.Bar.Stop()
	pterm.Success.Println(fmt.Sprintf("端口服探测完成，发现端口数量为【%d】条", len(engine.PortServiceList)))
	if common.Method == "port" {
		report.Port(common.Rstfile+".xlsx", output.PortList)
		return
	}
	//漏洞扫描
	scanvul := options.NewDefaultScanVul(utils.GetUrlList(common.UrlFile))
	pterm.Info.Println("开始进行漏洞和web指纹扫描")
	scanvul.ServicePortList = engine.PortServiceList
	VulEngine := cmd.NewScanEngine(scanvul)
	VulEngine.Scan()
	VulEngine.Bar.Stop()
	report.Port(common.Rstfile+".xlsx", output.PortList)
	report.WebFingerReport(common.Rstfile+".xlsx", model.WebFingerList)
	report.WeakPasswordReport(common.Rstfile+".xlsx", model.WeakPasswdList)
	report.PluginReport(common.Rstfile+".xlsx", model.PluginList)
	pterm.Success.Println("漏洞和指纹扫描已经结束")
	//指纹扫描
}

//control+c 退出的时候保存端口扫描结果和指纹扫描结果
func Finderlist() {
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt)
	select {
	case sig := <-sigChan:
		pterm.Warning.Println("退去之前将自动保存现有的结果：", sig)
		//fmt.Println(model.ResultReport)
		report.Port(common.Rstfile+".xlsx", output.PortList)
		report.WebFingerReport(common.Rstfile+".xlsx", model.WebFingerList)
		report.WeakPasswordReport(common.Rstfile+".xlsx", model.WeakPasswdList)
		report.PluginReport(common.Rstfile+".xlsx", model.PluginList)
		os.Exit(0)
	}
}
