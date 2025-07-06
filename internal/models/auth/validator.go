package auth

import (
	"errors"
	"regexp"
	"strings"
)

var emailRegex = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func (a *AuthRequest) Validate() error {
	
	if strings.TrimSpace(a.Email) == "" {
		return errors.New("email is required")
	}

	if !emailRegex.MatchString(a.Email) {
		return errors.New("invalid email format")
	}
	if strings.TrimSpace(a.Password) == "" {
		return errors.New("password is required")
	}
	return nil
}