package Gnbtscan

import (
	"fmt"
	"sync"
	"testing"
)

func TestNbtscan(t *testing.T) {
	ipList := make([]int, 255)
	wg := sync.WaitGroup{}
	wg.Add(255)
	for index := range ipList {
		ip := fmt.Sprintf("192.168.120.%d", index)
		go func() {
			result, err := Scan(ip)
			if err != nil {
				//t.Log(err)
			} else {
				t.Log(fmt.Sprintf("+%s -> %s", ip, result))
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
