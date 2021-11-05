package runner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pterm/pterm"

	"github.com/redtoolskobe/scaninfo/pkg/common"

	"go.uber.org/ratelimit"

	ps "github.com/redtoolskobe/scaninfo/pkg/common/ipparser"

	rc "github.com/redtoolskobe/scaninfo/pkg/common/rangectl"

	"github.com/redtoolskobe/scaninfo/pkg/output"
)

type Addr struct {
	ip   string
	port uint64
}

type Engine struct {
	TaskIps     []rc.Range //IP列表
	TaskPorts   []rc.Range //端口列表
	ExcdPorts   []rc.Range // 待排除端口
	ExcdIps     []rc.Range // 待排除的Ip
	WorkerCount int        //协程数据
	TaskChan    chan Addr  // 传递待扫描的ip端口对
	//DoneChan chan struct{}  // 任务完成通知
	Wg              *sync.WaitGroup
	Options         *common.Options
	Count           int
	ComCount        int64
	Writer          output.Writer
	Ctx             context.Context
	Bar             *pterm.ProgressbarPrinter
	Ticker          *time.Ticker
	PortServiceList []*output.ResultEvent
}

//创建引擎
func CreateEngine(option *common.Options) *Engine {

	if option.Limit > 1 {
		option.Limiter = ratelimit.New(option.Limit)
	} else {
		option.Limiter = ratelimit.NewUnlimited()
	}

	return &Engine{
		TaskChan:    make(chan Addr, option.NumThreads),
		WorkerCount: option.NumThreads,
		Wg:          &sync.WaitGroup{},
		Options:     option,
	}
}

// 扫描任务创建
func (e *Engine) Scheduler() {
	for i := 0; i < e.WorkerCount; i++ {
		e.worker(e.TaskChan, e.Wg)
	}
}

func (e *Engine) Run() {
	e.Wg.Add(e.WorkerCount)
	e.Ticker = time.NewTicker(time.Second * 1)
	go func(t *time.Ticker) {
		for {
			<-t.C
			e.Bar.Current = int(e.ComCount)
			e.Bar.Add(0)
		}
	}(e.Ticker)
	go e.Scheduler()
	e.randomScan()
	// 扫描任务发送完成，关闭通道
	//fmt.Println("Task Add done")
	//pterm.Success.Println("已关闭TaskChan,Bar进度条")
	//e.Ticker.Stop()
	e.Bar.Stop()
	close(e.TaskChan)
	e.Ticker.Stop()
	return
}

func (e *Engine) randomScan() {
	// 投机取巧，打乱端口顺序，遍历ip扫描
	var portlist = make(map[int]uint64)
	var index int
	var addr Addr

	//得到端口IPLIST
	for _, ports := range e.TaskPorts {
		for port := ports.Begin; port <= ports.End; port++ {
			portlist[index] = port
			index++
		}
	}

	e.Count = len(e.Options.IpList) * len(portlist)
	e.Bar, _ = pterm.DefaultProgressbar.WithTotal(e.Count).WithTitle("[Port Scan]").WithRemoveWhenDone(true).Start()
	for _, ip := range e.Options.IpList {
		for _, po := range portlist {
			addr.ip = ip
			addr.port = po
			select {
			case <-e.Ctx.Done():
				pterm.Success.Println("子线程Scan扫描已经结束停止任务列表Chan")
				e.Ticker.Stop()
				for len(e.TaskChan) > 0 {
					<-e.TaskChan
				}
				return
			default:
				e.TaskChan <- addr
			}
		}
	}

}

//初始化引擎
func (e *Engine) Parser() error {
	var err error
	e.Writer, err = output.NewStandardWriter()
	if err != nil {
		return err
	}
	var ports []string
	// TODO:: 待增加排除ip和排除端口流程

	for _, ipstr := range e.Options.CmdIps {
		if ps.IsIP(ipstr) || ps.IsIPRange(ipstr) {
			result, err := rc.ParseIpv4Range(ipstr)
			if err != nil {
				fmt.Println("Error occured while parse iprange")
				return err
			}

			e.TaskIps = append(e.TaskIps, result)
		} else {
			// 说明是域名，需要对域名进行解析
			ips, mask, err := ps.DomainToIp(ipstr)
			if err != nil {
				fmt.Println(err)
				return err
			}
			for _, ip := range ips {
				addr := ip
				if mask != "" {
					addr = ip + "/" + mask
				}

				result, err := rc.ParseIpv4Range(addr)

				if err != nil {
					fmt.Println("Error occured while parse iprange")
					return err
				}

				e.TaskIps = append(e.TaskIps, result)
			}
		}
	}

	if e.Options.IpFile != "" {
		rst, err := rc.ParseIPFromFile(e.Options.IpFile)
		if err == nil {
			for _, r := range rst {
				e.TaskIps = append(e.TaskIps, r)
			}
		}
	}

	if len(e.Options.ExcIps) != 0 {
		for _, ipstr := range e.Options.ExcIps {
			if ps.IsIP(ipstr) || ps.IsIPRange(ipstr) {
				result, err := rc.ParseIpv4Range(ipstr)
				if err != nil {
					fmt.Println("Error occured while parse iprange")
					return err
				}

				e.ExcdIps = append(e.ExcdIps, result)
			} else {
				// 说明是域名，需要对域名进行解析
				ips, mask, err := ps.DomainToIp(ipstr)
				if err != nil {
					fmt.Println(err)
					return err
				}
				for _, ip := range ips {
					addr := ip
					if mask != "" {
						addr = ip + "/" + mask
					}

					result, err := rc.ParseIpv4Range(addr)

					if err != nil {
						fmt.Println("Error occured while parse iprange")
						return err
					}

					e.ExcdIps = append(e.ExcdIps, result)
				}
			}
		}

		for _, ipe := range e.ExcdIps {
			for i := 0; i < len(e.TaskIps); i++ {
				if res, ok := (e.TaskIps[i]).RemoveExcFromTaskIps(ipe); ok {
					e.TaskIps = append(e.TaskIps, res)
				}
			}
		}
	}

	// 说明有自定义端口
	if len(e.Options.CmdPorts) != 0 {
		ports = e.Options.CmdPorts
	} else {
		if !e.Options.CmdT1000 {
			// Top100端口扫描
			ports = common.Top100Ports

		} else {
			// Top1000端口扫描
			ports = common.Top1000Ports
		}
	}

	// 解析命令行端口范围
	for _, portstr := range ports {
		result, err := rc.ParsePortRange(portstr)
		if err != nil {
			fmt.Println(err)
			return err
		}

		e.TaskPorts = append(e.TaskPorts, result)
	}

	// 解析待排除端口范围
	if len(e.Options.ExcPorts) != 0 {
		for _, portstr := range e.Options.ExcPorts {
			result, err := rc.ParsePortRange(portstr)
			if err != nil {
				fmt.Println(err)
				return err
			}

			e.ExcdPorts = append(e.ExcdPorts, result)
		}

		// range出来的其实是原始值的拷贝，因此，这里需要对原始值进行修改时，不能使用range
		for _, exp := range e.ExcdPorts {
			for i := 0; i < len(e.TaskPorts); i++ {
				if res, ok := (e.TaskPorts[i]).RemoveExcFromTaskIps(exp); ok {
					e.TaskPorts = append(e.TaskPorts, res)
				}
			}
		}
	}

	// fmt.Println(e.TaskPorts)
	// fmt.Println(e.ExcdPorts)
	return nil
}
