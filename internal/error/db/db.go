package db

type ErrorMessages struct {
	ConnectionFailed   string
	QueryFailed        string
	InsertFailed       string
	UpdateFailed       string
	UserCreationFailed string
	UserQueryFailed    string
	EmailQueryFailed   string
}

var Error = ErrorMessages{
	ConnectionFailed:   "failed to connect to database",
	QueryFailed:        "database query failed",
	InsertFailed:       "database insert failed",
	UpdateFailed:       "database update failed",
	UserCreationFailed: "failed to create user",
	UserQueryFailed:    "failed to query user",
	EmailQueryFailed:   "failed to query user email",
}
