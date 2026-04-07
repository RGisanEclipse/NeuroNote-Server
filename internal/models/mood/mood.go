package mood

type Request struct {
	Mood   string `json:"mood"`
	Reason string `json:"reason,omitempty"`
}

type RequestEntry struct {
	Days int `json:"days"`
}
