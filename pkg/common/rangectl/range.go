package rangectl

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	ps "github.com/redtoolskobe/scaninfo/pkg/common/ipparser"
)

type Range struct {
	Begin uint64
	End   uint64
}

/**
  RemoveExcFromTaskIps 从任务范围内移除需要排除的Ip或端口
  返回值：
  1. 表示任务列表范围，返回值2有效时才有意义
  2. 表示返回值是否有效，只有排除范围把任务列表分成两段时才有效
*/
func (r *Range) RemoveExcFromTaskIps(exclude Range) (Range, bool) {
	var split Range
	var tmp = *r

	if r.Begin > exclude.End || r.End < exclude.Begin {
		return Range{}, false
	}

	if r.Begin >= exclude.Begin && r.End <= exclude.End {
		*r = Range{}
		return Range{}, false
	}

	if r.Begin >= exclude.Begin && r.End > exclude.End {
		r.Begin = exclude.End + 1
		return Range{}, false
	}

	if r.Begin < exclude.Begin && r.End <= exclude.End {
		r.End = exclude.Begin - 1
		return Range{}, false
	}

	if r.Begin < exclude.Begin && r.End > exclude.End {
		r.End = exclude.Begin - 1
		split.Begin = exclude.End + 1
		split.End = tmp.End

		return split, true
	}

	return Range{}, false
}

// ParsePortRange 解析自定义端口范围
func ParsePortRange(port string) (Range, error) {
	var result Range
	port = strings.TrimSpace(port)
	if strings.Contains(port, "-") {
		prange := strings.Split(port, "-")
		start := prange[0]
		stop := prange[1]

		begin, err := strconv.Atoi(start)
		if err != nil {
			return Range{}, err
		}

		end, err := strconv.Atoi(stop)
		if err != nil {
			return Range{}, err
		}

		result.Begin = uint64(begin)
		result.End = uint64(end)
	} else {
		// 单个端口
		num, err := strconv.Atoi(port)
		if err != nil {
			return Range{}, err
		}

		result.Begin = uint64(num)
		result.End = uint64(num)
	}

	if result.Begin > result.End || result.Begin > 65536 || result.End > 65535 {
		return Range{}, errors.New("port range failed")
	}

	return result, nil
}

// ParseIpv4Range 解析Ip地址范围，
func ParseIpv4Range(ip string) (Range, error) {
	var result Range

	index := strings.Index(ip, "/")
	if index != -1 {
		ips, err := ps.CidrParse(ip)
		if err != nil {
			fmt.Println(err)
			return Range{}, err
		}

		begin, err := ps.ParseIPv4(ips[0])
		if err != nil {
			fmt.Println(err)
			return Range{}, err
		}

		result.Begin = begin

		end, err := ps.ParseIPv4(ips[len(ips)-1])
		if err != nil {
			fmt.Println(err)
			return Range{}, err
		}

		result.End = end

		return result, nil

	}

	index = strings.Index(ip, "-")
	if index != -1 {
		ips := strings.Split(ip, "-")

		begin, err := ps.ParseIPv4(ips[0])
		if err != nil {
			return Range{}, err
		}

		result.Begin = begin

		end, err := ps.ParseIPv4(ips[1])
		if err != nil {
			return Range{}, err
		}

		result.End = end

		if end < begin {
			return Range{}, errors.New("End ip is large than start ip")
		}

		return result, nil
	}

	// 说明是单个的ip
	num, err := ps.ParseIPv4(ip)
	if err != nil {
		return Range{}, err
	}

	result.Begin = num
	result.End = num

	return result, nil
}

func ParseIPFromFile(path string) ([]Range, error) {
	var ips []Range
	p, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if p.IsDir() {
		return nil, fmt.Errorf("could not input a dir: %s", path)
	}

	input, err := os.Open(path)

	if err != nil {
		return nil, fmt.Errorf("open file error: %s", path)
	}

	scanner := bufio.NewScanner(input)

	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip == "" {
			continue
		}
		if ps.IsIP(ip) || ps.IsIPRange(ip) {
			rst, err := ParseIpv4Range(ip)
			if err != nil {
				continue
			}
			ips = append(ips, rst)
		} else {
			tmp_ips, mask, err := ps.DomainToIp(ip)
			if err != nil {
				fmt.Println(err)
				continue
			}
			for _, ip := range tmp_ips {
				addr := ip
				if mask != "" {
					addr = ip + "/" + mask
				}
				result, err := ParseIpv4Range(addr)

				if err != nil {
					fmt.Println("Error occured while parse iprange")
					continue
				}
				ips = append(ips, result)
			}
		}
	}
	return ips, nil
}
