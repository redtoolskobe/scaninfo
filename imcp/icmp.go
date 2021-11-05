package imcp

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/redtoolskobe/scaninfo/pkg/common"

	"github.com/pterm/pterm"

	"github.com/redtoolskobe/scaninfo/utils"
	"golang.org/x/net/icmp"
)

var (
	AliveHosts []string
	OS         = runtime.GOOS
	ExistHosts = make(map[string]struct{})
	livewg     sync.WaitGroup
)

func ICMPRun(hostslist []string, Ping bool) []string {
	spinnerSuccess, _ := pterm.DefaultSpinner.Start("正在进行IMCP存活主机探测... (请等待)")
	chanHosts := make(chan string, common.IcmpThreds)
	go func() {
		for ip := range chanHosts {
			if _, ok := ExistHosts[ip]; !ok && utils.IsContain(hostslist, ip) {
				ExistHosts[ip] = struct{}{}
				AliveHosts = append(AliveHosts, ip)
			}
			livewg.Done()
		}
	}()

	if Ping == true {
		//使用ping探测
		RunPing(hostslist, chanHosts)
	} else {
		//优先尝试监听本地icmp,批量探测
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err == nil {
			RunIcmp1(hostslist, conn, chanHosts)
		} else {
			//尝试无监听icmp探测
			conn, err := net.DialTimeout("ip4:icmp", "127.0.0.1", 3*time.Second)
			if err == nil {
				go conn.Close()
				RunIcmp2(hostslist, chanHosts)
			} else {
				pterm.Warning.Println("使用ICMP扫描请确认是否为sudo权限,已切换成PING扫描")
				//使用ping探测
				//global.GVA_LOG_fscan.Warn(fmt.Sprintf("使用ICMP扫描请确认是否为sudo权限,已切换成PING扫描"), zap.String("scan", "FSCAN"))
				RunPing(hostslist, chanHosts)
			}
		}
	}

	livewg.Wait()
	close(chanHosts)
	spinnerSuccess.Success(fmt.Sprintf("imcp存活主机扫描结束,存活主机数量为【%d】台", len(AliveHosts)))
	return AliveHosts
}

func RunIcmp1(hostslist []string, conn *icmp.PacketConn, chanHosts chan string) {
	endflag := false
	go func() {
		for {
			if endflag == true {
				return
			}
			msg := make([]byte, 100)
			_, sourceIP, _ := conn.ReadFrom(msg)
			if sourceIP != nil {
				livewg.Add(1)
				chanHosts <- sourceIP.String()
			}
		}
	}()

	for _, host := range hostslist {
		dst, _ := net.ResolveIPAddr("ip", host)
		IcmpByte := makemsg(host)
		conn.WriteTo(IcmpByte, dst)
	}
	//根据hosts数量修改icmp监听时间
	start := time.Now()
	for {
		if len(AliveHosts) == len(hostslist) {
			break
		}
		since := time.Now().Sub(start)
		var wait time.Duration
		switch {
		case len(hostslist) <= 256:
			wait = time.Second * 3
		default:
			wait = time.Second * 6
		}
		if since > wait {
			break
		}
	}
	endflag = true
	conn.Close()
}

func RunIcmp2(hostslist []string, chanHosts chan string) {
	num := 1000
	if len(hostslist) < num {
		num = len(hostslist)
	}
	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if icmpalive(host) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
	close(limiter)
}

func icmpalive(host string) bool {
	startTime := time.Now()
	conn, err := net.DialTimeout("ip4:icmp", host, 6*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	if err := conn.SetDeadline(startTime.Add(6 * time.Second)); err != nil {
		return false
	}
	msg := makemsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}

	return true
}

func RunPing(hostslist []string, chanHosts chan string) {
	var bsenv = ""
	if OS != "windows" {
		bsenv = "/bin/bash"
	}
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 50)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if ExecCommandPing(host, bsenv) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
}

func ExecCommandPing(ip string, bsenv string) bool {
	var command *exec.Cmd
	if OS == "windows" {
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	} else if OS == "linux" {
		command = exec.Command(bsenv, "-c", "ping -c 1 -w 1 "+ip+" >/dev/null && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	} else if OS == "darwin" {
		command = exec.Command(bsenv, "-c", "ping -c 1 -W 1 "+ip+" >/dev/null && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		return false
	}
	if err = command.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(outinfo.String(), "true") {
			return true
		} else {
			return false
		}
	}
}

func makemsg(host string) []byte {
	msg := make([]byte, 40)
	id0, id1 := genIdentifier(host)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = genSequence(1)
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)
	return msg
}

func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	answer := uint16(^sum)
	return answer
}

func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}

func genIdentifier(host string) (byte, byte) {
	return host[0], host[1]
}
