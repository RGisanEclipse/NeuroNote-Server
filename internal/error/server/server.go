package server

type ServerErrorMessages struct {
	MissingEnvVars         string
	StartupFailed          string
	ShutdownFailed         string
	InternalError          string
	InvalidBody            string
	TooManyRequests        string
	HTTPServerError        string
	BadRequest             string
	Unauthorized           string
	JSONMarshalError       string
	JSONUnmarshalError     string
	RequestCreationFailure string
	RequestDeliveryFailure string
	Non200ResponseError    string
}

var ServerError = ServerErrorMessages{
	MissingEnvVars:         "no .env file found. Server cannot start",
	StartupFailed:          "server startup failed",
	ShutdownFailed:         "server shutdown error",
	InternalError:          "internal server error",
	InvalidBody:            "invalid request body",
	TooManyRequests:        "too many requests",
	HTTPServerError:        "HTTP server error",
	BadRequest:             "bad request",
	Unauthorized:           "unauthorized access",
	JSONMarshalError:       "error marshalling JSON",
	JSONUnmarshalError:     "error unmarshalling JSON",
	RequestCreationFailure: "failed to create request",
	RequestDeliveryFailure: "failed to send Brevo request",
	Non200ResponseError:    "received non-200 response from API",
}