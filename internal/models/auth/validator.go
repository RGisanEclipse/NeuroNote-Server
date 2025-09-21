package auth

import (
	"regexp"
	"strings"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
)

var (
	emailRegex       = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	uppercaseRegex   = regexp.MustCompile(`.*[A-Z]+.*`)
	lowercaseRegex   = regexp.MustCompile(`.*[a-z]+.*`)
	digitRegex       = regexp.MustCompile(`.*[0-9]+.*`)
	specialCharRegex = regexp.MustCompile(`.*[!@#$%^&*(),.?\":{}|<>]+.*`)
	whitespaceRegex  = regexp.MustCompile(`.*\s+.*`)
)

func (a *Request) Validate() error {

	if err := ValidateEmail(a.Email); err != nil {
		return err
	}

	if err := ValidatePassword(a.Password); err != nil {
		return err
	}

	return nil
}

func ValidateEmail(email string) error {

	if strings.TrimSpace(email) == "" {
		return appError.EmailRequired
	}

	if !emailRegex.MatchString(email) {
		return appError.EmailInvalid
	}

	return nil
}

func ValidatePassword(password string) error {

	if strings.TrimSpace(password) == "" {
		return appError.PasswordRequired
	}

	if len(password) < 8 {
		return appError.PasswordTooShort
	}

	if len(password) > 32 {
		return appError.PasswordTooLong
	}

	if !uppercaseRegex.MatchString(password) {
		return appError.PasswordMissingUppercase
	}

	if !lowercaseRegex.MatchString(password) {
		return appError.PasswordMissingLowercase
	}

	if !digitRegex.MatchString(password) {
		return appError.PasswordMissingDigit
	}

	if !specialCharRegex.MatchString(password) {
		return appError.PasswordMissingSpecialChar
	}

	if whitespaceRegex.MatchString(password) {
		return appError.PasswordContainsWhitespace
	}

	return nil
}
