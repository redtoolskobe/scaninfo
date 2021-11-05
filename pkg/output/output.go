package output

import (
	"regexp"
	"time"

	"github.com/redtoolskobe/scaninfo/global"
	"go.uber.org/zap"
)

// Writer is an interface which writes output to somewhere for nuclei events.
type Writer interface {
	Write(*ResultEvent, *[]*ResultEvent) error
	// Request logs a request in the trace log
}

type Info struct {
	Banner  string
	Service string
	Cert    string
	Url     string
}
type ResultEvent struct {
	WorkingEvent interface{} `json:"WorkingEvent"`
	Info         *Info       `json:"info,inline"`
	Time         time.Time   `json:"time"`
	Target       string      `json:"Target"`
	Ip           string      `json:"ip"`
	Port         uint64      `json:"port"`
	Url          string
}

var PortList = []*ResultEvent{}

type StandardWriter struct {
}

var decolorizerRegex = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)

func NewStandardWriter() (*StandardWriter, error) {
	writer := &StandardWriter{}
	return writer, nil
}

// Write writes the event to file and/or screen.
func (w *StandardWriter) Write(event *ResultEvent, portlist *[]*ResultEvent) error {
	if event == nil {
		return nil
	}
	global.Log.Info("port", zap.String("ip", event.Ip), zap.Uint64("port", event.Port), zap.String("service", event.Info.Service),
		zap.String("Banner", event.Info.Banner), zap.String("url", event.Info.Url))
	event.Time = time.Now()
	*portlist = append(*portlist, event)
	//model.ResultReport.PortList = append(model.ResultReport.PortList, event)
	PortList = append(PortList, event)
	return nil
}

type JSONTraceRequest struct {
	IP    string `json:"ip"`
	Port  string `json:"port"`
	Error string `json:"error"`
	Type  string `json:"type"`
}
