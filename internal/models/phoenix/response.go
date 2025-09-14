package phoenix

type Response struct {
	Success   bool        `json:"status"`
	Message   string      `json:"message,omitempty"`
	MessageId string      `json:"message_id,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
}
