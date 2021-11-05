package common

import (
	"fmt"
	"time"

	"github.com/projectdiscovery/gologger"

	"github.com/pterm/pterm"

	"github.com/projectdiscovery/clistats"
)

type Progress interface {
	Init(Count int64)
	IncrementRequests()
	Stop()
}

type StatsTicker struct {
	active       bool
	tickDuration time.Duration
	stats        clistats.StatisticsClient
	Bar          *pterm.ProgressbarPrinter
}

func NewStatsTicker(duration int, active bool) (Progress, error) {
	var tickDuration time.Duration
	if active {
		tickDuration = time.Duration(duration) * time.Second
	} else {
		tickDuration = -1
	}

	progress := &StatsTicker{}

	stats, err := clistats.New()
	if err != nil {
		return nil, err
	}
	progress.active = active
	progress.stats = stats
	progress.tickDuration = tickDuration

	return progress, nil
}

func (p *StatsTicker) IncrementRequests() {
	p.stats.IncrementCounter("requests", 1)
}

func (p *StatsTicker) Init(Count int64) {
	p.stats.AddStatic("startedAt", time.Now())
	p.stats.AddCounter("requests", uint64(0))
	p.Bar, _ = pterm.DefaultProgressbar.WithTotal(int(Count)).WithTitle("[Port Scan]").Start()
	if p.active {
		if err := p.stats.Start(p.printCallback, p.tickDuration); err != nil {
			fmt.Println(err)
		}
	}
}

func (p *StatsTicker) printCallback(stats clistats.StatisticsClient) {
	requests, _ := stats.GetCounter("requests")
	time.Sleep(1 * time.Second)
	fmt.Print("")
	p.Bar.Current = int(requests)
	p.Bar.Add(0)
}

func (p *StatsTicker) Stop() {
	if p.active {
		// Print one final summary
		p.printCallback(p.stats)
		if err := p.stats.Stop(); err != nil {
			gologger.Warning().Msgf("Couldn't stop statistics: %s", err)
		}
	}
}
