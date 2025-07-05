package server

type ServerErrorMessages struct {
	MissingEnvVars  string
	StartupFailed   string
	ShutdownFailed  string
	InternalError   string
	InvalidBody     string
	TooManyRequests string
	HTTPServerError string
}

var ServerError = ServerErrorMessages{
	MissingEnvVars:  "No .env file found. Server cannot start",
	StartupFailed:   "Server startup failed",
	ShutdownFailed:  "Server shutdown error",
	InternalError:   "Internal server error",
	InvalidBody:     "Invalid request body",
	TooManyRequests:  "Too many requests",
	HTTPServerError:  "HTTP server error",
}