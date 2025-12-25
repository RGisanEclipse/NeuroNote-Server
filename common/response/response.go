package response

import (
	"encoding/json"
	"net/http"

	apperror "github.com/RGisanEclipse/NeuroNote-Server/common/error"
)

// Response represents a successful API response
type Response struct {
	Success  bool        `json:"success"`
	Status   int         `json:"status"`
	Response interface{} `json:"response"`
}

// WriteJSON writes a JSON response
func WriteJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// WriteSuccess writes a success response
func WriteSuccess(w http.ResponseWriter, data interface{}) {
	status := http.StatusOK
	response := Response{
		Success:  true,
		Status:   status,
		Response: data,
	}
	WriteJSON(w, status, response)
}

// WriteError writes an error response with error code
func WriteError(w http.ResponseWriter, errorCode *apperror.Code, data ...interface{}) {
	errorResponse := map[string]interface{}{
		"errorCode": errorCode.Code,
		"message":   errorCode.Message,
	}
	if len(data) > 0 {
		errorResponse["data"] = data[0]
	}

	response := Response{
		Success:  false,
		Status:   errorCode.Status,
		Response: errorResponse,
	}
	WriteJSON(w, errorCode.Status, response)
}
