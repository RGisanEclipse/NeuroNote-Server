package auth

import (
	"errors"
	"regexp"
	"strings"
	authErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/auth"
)

var (
	emailRegex = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	uppercaseRegex = regexp.MustCompile(`.*[A-Z]+.*`)
	lowercaseRegex = regexp.MustCompile(`.*[a-z]+.*`)
	digitRegex = regexp.MustCompile(`.*[0-9]+.*`)
	specialCharRegex = regexp.MustCompile(`.*[!@#$%^&*(),.?\":{}|<>]+.*`)
	whitespaceRegex = regexp.MustCompile(`.*\s+.*`)
)

func (a *AuthRequest) Validate() error {

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
		return errors.New(authErr.AuthError.EmailRequired)
	}

	if !emailRegex.MatchString(email) {
		return errors.New(authErr.AuthError.InvalidEmail)
	}

	return nil
}

func ValidatePassword(password string) error {

	if strings.TrimSpace(password) == "" {
		return errors.New(authErr.AuthError.PasswordRequired)
	}

	if len(password) < 8 {
		return errors.New(authErr.AuthError.PasswordTooShort)
	}

	if len(password) > 32 {
		return errors.New(authErr.AuthError.PasswordTooLong)
	}

	if !uppercaseRegex.MatchString(password){
		return errors.New(authErr.AuthError.PasswordMissingUppercase)
	}

	if !lowercaseRegex.MatchString(password) {
		return errors.New(authErr.AuthError.PasswordMissingLowercase)
	}

	if !digitRegex.MatchString(password) {
		return errors.New(authErr.AuthError.PasswordMissingDigit)
	}

	if !specialCharRegex.MatchString(password) {
		return errors.New(authErr.AuthError.PasswordMissingSpecialCharacter)
	}


	if whitespaceRegex.MatchString(password) {
		return errors.New(authErr.AuthError.PasswordContainsWhitespace)
	}


	return nil
}
