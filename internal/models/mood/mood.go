package mood

type Request struct {
	Mood      string `json:"mood"`
	Reason    string `json:"reason,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"` // epoch; if non-zero, used as CreatedAt instead of server time
}

type RequestEntry struct {
	Days int `json:"days"`
}
