package mocks

import appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"

// NoError Helper function to create an empty error code for success cases
func NoError() *appError.Code {
	return nil
}
