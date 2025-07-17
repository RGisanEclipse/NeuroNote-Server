// internal/service/auth/service.go
package auth

import "context"

type AuthService interface {
	Signup(ctx context.Context, email, password string) (uint, string, error)
	Signin(ctx context.Context, email, password string) (uint, string, error)
}