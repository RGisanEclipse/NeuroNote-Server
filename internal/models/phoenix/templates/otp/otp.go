package otp

import (
	"strings"
	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix"
	forgotPassword "github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix/templates/otp/forgot_password"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix/templates/otp/signup"
)

var bodyMap = map[string]string{
	string(PurposeSignup):         signup.BodyHTML,
	string(PurposeForgotPassword): forgotPassword.BodyHTML,
}

func GetTemplate(otp string, purpose string) (model.EmailTemplate, error) {

	body, exists := bodyMap[purpose]

	if !exists {
		return model.EmailTemplate{}, appError.OtpInvalidPurpose
	}

	return model.EmailTemplate{
		Subject:  "Welcome to NeuroNote!",
		BodyHTML: strings.Replace(body, "{{.OTP}}", otp, 1),
	}, nil
}
