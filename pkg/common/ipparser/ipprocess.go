package ipparser

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
)

/**
  这个文件主要是包含一些对ip地址进行处理的函数和对域名进行解析相关的函数
*/

// ValidIpv4 判断Ip地址是否合法
func ValidIpv4(ip string) bool {
	if valid := net.ParseIP(ip); valid != nil {
		return true
	}

	return false
}

// 根据域名查找ip，一个域名可能对应多个ip
func DomainToIp(domain string) ([]string, string, error) {
	var fields []string
	var mask string
	var host = domain

	if strings.Contains(domain, "/") {
		fields = strings.Split(domain, "/")
		host = fields[0]
		mask = fields[1]
	}

	//ips, err := net.LookupHost(host)
	ips, err := ipFilter(host)

	if err != nil {
		// TODO:: 记录日志
		fmt.Println(err)
		return nil, "", err
	}

	return ips, mask, nil
}

// ParseIPv4 把ipv4地址解析为整数
func ParseIPv4(ipstr string) (uint64, error) {

	ip := big.NewInt(0)
	tmp := net.ParseIP(ipstr).To4()
	if tmp == nil {
		return 0, errors.New("Wrong ip addr")
	}
	ip.SetBytes(tmp)

	return ip.Uint64(), nil
}

// UnParseIPv4 把整数解析成ip地址
func UnParseIPv4(ip uint64) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func IsIP(ip string) (b bool) {
	if m, _ := regexp.MatchString("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/{0,1}[0-9]{0,2}$", ip); !m {
		return false
	}

	return true
}

func IsIPRange(ip string) (b bool) {
	if m, _ := regexp.MatchString("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}-[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$", ip); !m {
		return false
	}

	return true
}

func CidrParse(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips = make([]string, 0, 100)
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// exclude ipv6 addr
func ipFilter(host string) ([]string, error) {
	tmp := make([]string, 0, 50)

	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		if IsIP(ip) {
			tmp = append(tmp, ip)
		}
	}

	return tmp, nil
}
