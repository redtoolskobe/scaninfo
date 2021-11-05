package common

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"go.uber.org/ratelimit"
)

type sliceValue []string

func newSliceValue(vals []string, p *[]string) *sliceValue {
	*p = vals
	return (*sliceValue)(p)
}

func (s *sliceValue) Set(val string) error {
	*s = sliceValue(strings.Split(val, ","))
	return nil
}

func (s *sliceValue) Get() interface{} {
	return []string(*s)
}

func (s *sliceValue) String() string {
	return strings.Join([]string(*s), ",")
}

var (
	cmdIps []string
	// cmdExPath  string
	cmdCofPath   string
	cmdPorts     []string
	cmdT1000     bool
	cmdRandom    bool
	NumThreads   int
	excPorts     []string // 待排除端口
	excIps       []string // 待排除Ip
	ipFile       string
	WebVulThreds int
	UrlFile      string
	Method       string
	nocolor      bool //彩色打印
	json         bool
	tracelog     string  //请求日志
	Rstfile      string  //文件保存
	tout         float64 //timeout
	nbtscan      bool
	limit        int
	Limiter      ratelimit.Limiter
	IcmpThreds   int
	ShowScanType bool
	FingerFile   string
	Noping       bool //是否为ping扫描默认为true
)

type Options struct {
	CmdIps []string
	// cmdExPath  string
	CmdCofPath  string
	CmdPorts    []string
	CmdT1000    bool
	CmdRandom   bool
	NumThreads  int
	IcmpThreads int
	ExcPorts    []string // 待排除端口
	ExcIps      []string // 待排除Ip
	IpFile      string
	Rstfile     string  //文件保存
	Tout        float64 //timeout
	Limit       int
	Limiter     ratelimit.Limiter
	IpList      []string //要扫描的主机列表
	AliveHosts  []string //存活的主机
}

var ScanMethodMap = map[string]string{
	"ftp":       "ftp",
	"ssh":       "ssh",
	"findnet":   "findnet",
	"netbios":   "netbios",
	"smb":       "smb",
	"mssql":     "mssql",
	"mysql":     "mysql",
	"psql":      "postgresql",
	"redis":     "redis",
	"mem":       "memcached",
	"mgo":       "mongodb",
	"all":       "all",
	"port":      "port",
	"ping":      "ping",
	"ms17010":   "1000001",
	"smbghost":  "1000002",
	"webfinger": "1000003",
}

var ScanTypeList = []string{"ftp", "ssh", "findnet", "netbios", "smb", "mssql", "mysql", "psql", "redis", "mem", "mgo", "all", "port", "ping", "ms17010", "smbghost", "webfinger"}

func NewDefaultOptions() *Options {
	return &Options{
		CmdCofPath:  "",
		CmdPorts:    cmdPorts,
		CmdT1000:    cmdT1000,
		NumThreads:  NumThreads,
		ExcPorts:    excPorts,
		ExcIps:      excIps,
		CmdIps:      cmdIps,
		IpFile:      ipFile,
		Rstfile:     Rstfile,
		Tout:        tout,
		Limit:       limit,
		Limiter:     ratelimit.NewUnlimited(),
		IpList:      []string{},
		AliveHosts:  []string{},
		IcmpThreads: IcmpThreds,
	}
}

/**
  命令行参数解析：
  -i: 输入的Ip地址或者域名,以逗号分隔. 例如192.168.1.1/24,scanme.nmap.org
  -e: 设置排除文件路径，排除文件内容为需要排除的ip地址列表
  -c: 配置文件路径，支持从配置文件中读取ip，地址列表
  -p: 需要扫描的端口列表，以逗号分隔，例如: 1-1000,3379,6379，和-p互斥
  -t1000: 布尔类型，默认是扫描top100，否则扫描top1000端口，和-p互斥
  -r: 布尔类型，表示扫描方式，随机扫描还是顺序扫描
*/
func init() {
	flag.Var(newSliceValue([]string{}, &cmdIps), "i", "set domain and ips")
	flag.StringVar(&ipFile, "l", "", "input ips file")
	flag.StringVar(&UrlFile, "uf", "", "input url file of webtitle scan")
	flag.StringVar(&FingerFile, "ff", "", "Custom specified file for finger")
	flag.Var(newSliceValue([]string{}, &cmdPorts), "p", "set port ranges to scan，default is top100")
	flag.BoolVar(&cmdT1000, "t1000", false, "scan top1000 ports")
	flag.BoolVar(&Noping, "np", false, "ping scan of host alive")
	flag.BoolVar(&ShowScanType, "show", false, "show scan type list")
	flag.StringVar(&Method, "m", "all", "Select scan type ,as: -m ssh (default al)")
	flag.IntVar(&NumThreads, "n", 900, "scan threads for port scan, between 1 and 2000")
	flag.IntVar(&IcmpThreds, "pt", 100, "imcp scan threds,default is 100 ")
	flag.IntVar(&WebVulThreds, "vt", 500, "web and vul scan threds,default is 500 ")
	flag.Var(newSliceValue([]string{}, &excPorts), "ep", "set port ranges to exclude")
	flag.Var(newSliceValue([]string{}, &excIps), "ei", "set ip ranges to exclude")
	flag.StringVar(&Rstfile, "o", "result", "save scan result file")
	flag.Float64Var(&tout, "t", 0.5, "scan port tcp connect time out default 0.5 second")
}

type Identification_Packet struct {
	Desc   string
	Packet []byte
}

var St_Identification_Packet [100]Identification_Packet

// 初始化IdentificationProtocol到内存中

func init() {
	for i, packet := range IdentificationProtocol {
		szinfo := strings.Split(packet, "#")
		data, err := hex.DecodeString(szinfo[1])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		St_Identification_Packet[i].Desc = szinfo[0]
		St_Identification_Packet[i].Packet = data
	}
}

func ArgsPrint() {
	fmt.Println(cmdIps)
	fmt.Println(cmdRandom)
	fmt.Println(cmdPorts)
	fmt.Println(excPorts)
}

/**
  configeFileParse 配置文件解析函数
  配置文件每行一条数据，可以是单个ip，域名，也可以是带掩码的ip和域名
*/
func ConfigeFileParse(path string) ([]string, error) {
	var err error
	var ips = make([]string, 0, 100)

	file, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer file.Close()

	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		// 去除空行
		if len(line) == 0 || line == "\r\n" {
			continue
		}

		// 以#开头的为注释内容
		if strings.Index(line, "#") == 0 {
			continue
		}

		ips = append(ips, line)
	}

	return ips, err
}
