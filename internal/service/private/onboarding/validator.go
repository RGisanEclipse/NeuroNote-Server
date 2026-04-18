package onboarding

import (
	appError "github.com/RGisanEclipse/AVYO-Server/common/error"
	om "github.com/RGisanEclipse/AVYO-Server/internal/models/onboarding"
)

// ValidateOnboardingData validates user onboarding input.
func ValidateOnboardingData(data om.Model) *appError.Code {
	if len(data.Name) == 0 {
		return appError.OBNameTooShort
	}

	if len(data.Name) > 50 {
		return appError.OBNameTooLong
	}

	if data.Age < 13 || data.Age > 100 {
		return appError.OBInvalidAge
	}

	if data.Gender != 0 && data.Gender != 1 {
		return appError.OBInvalidGender
	}

	return nil
}
