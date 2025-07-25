package server

type ServerErrorMessages struct {
	MissingEnvVars  string
	StartupFailed   string
	ShutdownFailed  string
	InternalError   string
	InvalidBody     string
	TooManyRequests string
	HTTPServerError string
	BadRequest      string
	Unauthorized	string
}

var ServerError = ServerErrorMessages{
	MissingEnvVars:   "no .env file found. Server cannot start",
	StartupFailed:    "server startup failed",
	ShutdownFailed:   "server shutdown error",
	InternalError:    "internal server error",
	InvalidBody:      "invalid request body",
	TooManyRequests:  "too many requests",
	HTTPServerError:  "HTTP server error",
	BadRequest: 	  "bad request",
	Unauthorized:    "unauthorized access",
}