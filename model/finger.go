package model

type PackFingers struct {
	Fingerprint []Fingers
}

//web 指纹结构体
type Fingers struct {
	Cms      string   `json:"cms"`
	Method   string   `json:"method"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
}
