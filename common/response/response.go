package response

import (
	"encoding/json"
	"net/http"

	apperror "github.com/RGisanEclipse/NeuroNote-Server/common/error"
)

// SuccessResponse represents a successful API response
type SuccessResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// WriteJSON writes a JSON response
func WriteJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// WriteSuccess writes a success response
func WriteSuccess(w http.ResponseWriter, data interface{}, message ...string) {
	response := SuccessResponse{
		Success: true,
		Data:    data,
	}
	if len(message) > 0 {
		response.Message = message[0]
	}
	WriteJSON(w, http.StatusOK, response)
}

// WriteError writes an error response with error code
func WriteError(w http.ResponseWriter, errorCode apperror.Code, data ...interface{}) {
	response := apperror.NewErrorResponse(errorCode.Code, errorCode.Message, errorCode.Status)
	if len(data) > 0 {
		response.Data = data[0]
	}
	WriteJSON(w, errorCode.Status, response)
}

// WriteErrorWithCode writes an error response using error code string
func WriteErrorWithCode(w http.ResponseWriter, code string, data ...interface{}) {
	if errorCode, exists := apperror.GetErrorByCode(code); exists {
		WriteError(w, errorCode, data...)
	} else {
		// Fallback to internal server error if code not found
		WriteError(w, apperror.ServerInternalError, data...)
	}
}
