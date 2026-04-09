package sync

import "encoding/json"

type Operation struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type SyncRequest struct {
	Operations []Operation `json:"operations"`
}

type OperationResult struct {
	Index   int    `json:"index"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type SyncResponse struct {
	Results   []OperationResult `json:"results"`
	Processed int               `json:"processed"`
	Failed    int               `json:"failed"`
}
