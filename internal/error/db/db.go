package db

type DBErrorMessages struct {
	ConnectionFailed   string
	QueryFailed        string
	InsertFailed       string
	UpdateFailed       string
	UserCreationFailed string
	UserQueryFailed    string
	EmailQueryFailed   string
}

var DBError = DBErrorMessages{
	ConnectionFailed:   "failed to connect to database",
	QueryFailed:        "database query failed",
	InsertFailed:       "database insert failed",
	UpdateFailed:       "database update failed",
	UserCreationFailed: "failed to create user",
	UserQueryFailed:    "failed to query user",
	EmailQueryFailed:   "failed to query user email",
}