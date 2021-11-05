package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/pterm/pterm"

	"github.com/redtoolskobe/scaninfo/pkg/log"

	"github.com/redtoolskobe/scaninfo/pkg/common"

	"github.com/redtoolskobe/scaninfo/run"
)

func init() {
	newHeader := pterm.HeaderPrinter{
		TextStyle:       pterm.NewStyle(pterm.BgCyan),
		BackgroundStyle: pterm.NewStyle(pterm.BgCyan),
		Margin:          20,
	}
	newHeader.Println("scan info  v1.1.0")
	pterm.FgRed.Println("本工具只做探测没有提供利用方式只供学习,请遵守国家网络安全.")
	pterm.FgRed.Println("扫描的时候可以手动停止结果会自动保存,-h查看使用说明-show查看支持的模块.")
	pterm.FgRed.Println("漏洞和指纹扫描的时候可能最后几个任务很慢,是因为弱口令爆破,可以手动control+c结束.")
	pterm.Warning.Println("默认使用TOP100端口,可以-p指定端口或者使用参数-t1000扫TOP1000.")
	flag.Parse()
	log.InitLog()
	if common.NumThreads < 1 || common.NumThreads > 2000 {
		fmt.Println("number of goroutine must between 1 and 2000")
		os.Exit(-1)
	}
	if common.ShowScanType {
		showmode()
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	run.Start(ctx)
	//time.Sleep(180 * time.Second)
	cancel()
	pterm.Success.Println("所有任务已经结束。")
}

func showmode() {
	fmt.Println("The specified scan type does not exist")
	fmt.Println("-m")
	for _, name := range common.ScanTypeList {
		fmt.Println("   [" + name + "]")
	}
	os.Exit(0)
}
