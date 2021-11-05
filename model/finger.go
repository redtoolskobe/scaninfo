package model

type PackFingers struct {
	Fingerprint []Fingers
}

type Fingers struct {
	Cms      string   `json:"cms"`
	Method   string   `json:"method"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
}
