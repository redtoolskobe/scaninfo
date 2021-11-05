package runner

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redtoolskobe/scaninfo/pkg/Ginfo/Ghttp"
	"github.com/redtoolskobe/scaninfo/pkg/common"
	"github.com/redtoolskobe/scaninfo/pkg/output"
)

func (e *Engine) Scanner(ip string, port uint64) {
	atomic.AddInt64(&e.ComCount, 1)
	var dwSvc int
	var iRule = -1
	var bIsIdentification = false
	var resultEvent *output.ResultEvent
	var packet []byte
	//var iCntTimeOut = 0
	//fmt.Println(req, "/", Count)
	// 端口开放状态，发送报文，获取响应
	// 先判断端口是不是优先识别协议端口
	for _, svc := range common.St_Identification_Port {
		if port == svc.Port {
			bIsIdentification = true
			iRule = svc.Identification_RuleId
			data := common.St_Identification_Packet[iRule].Packet

			dwSvc, resultEvent = e.SendIdentificationPacketFunction(data, ip, port)
			break
		}
	}
	if (dwSvc > common.UNKNOWN_PORT && dwSvc <= common.SOCKET_CONNECT_FAILED) || dwSvc == common.SOCKET_READ_TIMEOUT {
		e.Writer.Write(resultEvent, &e.PortServiceList)
		return
	}

	// 发送其他协议查询包
	for i := 0; i < common.IPacketMask; i++ {
		// 超时2次,不再识别
		if bIsIdentification && iRule == i {
			continue
		}
		if i == 0 {
			// 说明是http，数据需要拼装一下
			var szOption string
			if port == 80 {
				szOption = fmt.Sprintf("%s%s\r\n\r\n", common.St_Identification_Packet[0].Packet, ip)
			} else {
				szOption = fmt.Sprintf("%s%s:%d\r\n\r\n", common.St_Identification_Packet[0].Packet, ip, port)
			}
			packet = []byte(szOption)
		} else {
			packet = common.St_Identification_Packet[i].Packet
		}

		dwSvc, resultEvent = e.SendIdentificationPacketFunction(packet, ip, port)
		if (dwSvc > common.UNKNOWN_PORT && dwSvc <= common.SOCKET_CONNECT_FAILED) || dwSvc == common.SOCKET_READ_TIMEOUT {
			e.Writer.Write(resultEvent, &e.PortServiceList)
			return
		}
	}
	// 没有识别到服务，也要输出当前开放端口状态
	e.Writer.Write(resultEvent, &e.PortServiceList)
}

func (e *Engine) SendIdentificationPacketFunction(data []byte, ip string, port uint64) (int, *output.ResultEvent) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	even := &output.ResultEvent{
		Target: addr,
		Info:   &output.Info{},
		Ip:     ip,
		Port:   port,
	}

	//fmt.Println(addr)
	var dwSvc int = common.UNKNOWN_PORT
	conn, err := net.DialTimeout("tcp", addr, time.Duration(e.Options.Tout*1000)*time.Millisecond)
	if err != nil {
		// 端口是closed状态
		return common.SOCKET_CONNECT_FAILED, nil
	}

	defer conn.Close()

	// Write方法是非阻塞的

	if _, err := conn.Write(data); err != nil {
		// 端口是开放的
		return dwSvc, even
	}

	// 直接开辟好空间，避免底层数组频繁申请内存
	var fingerprint = make([]byte, 0, 65535)
	var tmp = make([]byte, 256)
	// 存储读取的字节数
	var num int
	var szBan string
	var szSvcName string

	// 这里设置成6秒是因为超时的时候会重新尝试5次，

	readTimeout := 2 * time.Second

	// 设置读取的超时时间为6s
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	for {
		// Read是阻塞的
		n, err := conn.Read(tmp)
		if err != nil {
			// 虽然数据读取错误，但是端口仍然是open的
			// fmt.Println(err)
			if err != io.EOF {
				dwSvc = common.SOCKET_READ_TIMEOUT
				// fmt.Printf("Discovered open port\t%d\ton\t%s\n", port, ip)
			}
			break
		}

		if n > 0 {
			num += n
			fingerprint = append(fingerprint, tmp[:n]...)
		} else {
			// 虽然没有读取到数据，但是端口仍然是open的
			// fmt.Printf("Discovered open port\t%d\ton\t%s\n", port, ip)
			break
		}
	}
	// 服务识别
	if num > 0 {
		dwSvc = common.ComparePackets(fingerprint, num, &szBan, &szSvcName)
		//if len(szBan) > 15 {
		//	szBan = szBan[:15]
		//}
		if dwSvc > common.UNKNOWN_PORT && dwSvc < common.SOCKET_CONNECT_FAILED {
			//even.WorkingEvent = "found"
			if szSvcName == "ssl/tls" || szSvcName == "http" {
				rst := Ghttp.GetHttpTitle(ip, Ghttp.HTTPorHTTPS, int(port))
				even.WorkingEvent = rst
				even.Info.Url = rst.URL
				cert, err0 := Ghttp.GetCert(ip, int(port))
				if err0 != nil {
					cert = ""
				}
				even.Info.Cert = cert
			} else {
				even.Info.Banner = strings.TrimSpace(szBan)
			}
			even.Info.Service = szSvcName
			even.Time = time.Now()
			// fmt.Printf("Discovered open port\t%d\ton\t%s\t\t%s\t\t%s\n", port, ip, szSvcName, strings.TrimSpace(szBan))
			//Writer.Write(even)
			//return dwSvc, even
		}
	}

	return dwSvc, even
}
