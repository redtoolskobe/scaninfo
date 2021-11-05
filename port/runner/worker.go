package runner

import (
	"sync"
)

func (e *Engine) worker(res chan Addr, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()
		for addr := range res {
			e.Options.Limiter.Take()
			e.Scanner(addr.ip, addr.port)
		}

	}()
}
