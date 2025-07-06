package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	authhandler "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/auth"
	authmodel   "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
)

// ────────────────────────────────────────────────────────────
// Mock service that satisfies authservice.Service
// ────────────────────────────────────────────────────────────
type mockAuthService struct{ mock.Mock }

func (m *mockAuthService) Signup(ctx context.Context, email, pw string) (string, error) {
	args := m.Called(ctx, email, pw)
	return args.String(0), args.Error(1)
}
func (m *mockAuthService) Signin(ctx context.Context, email, pw string) (string, error) {
	args := m.Called(ctx, email, pw)
	return args.String(0), args.Error(1)
}

// ────────────────────────────────────────────────────────────
// Signup handler tests
// ────────────────────────────────────────────────────────────
func TestSignupHandler_Success(t *testing.T) {
	mockSvc := new(mockAuthService)
	mockSvc.On("Signup", mock.Anything, "test@example.com", "123456").
		Return("mock-token", nil)

	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email: "test@example.com", Password: "123456",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockSvc.AssertExpectations(t)
}

func TestSignupHandler_EmailExists(t *testing.T) {
	mockSvc := new(mockAuthService)
	mockSvc.On("Signup", mock.Anything, "exists@example.com", "123456").
		Return("", errors.New("email already exists"))

	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email: "exists@example.com", Password: "123456",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	mockSvc.AssertExpectations(t)
}

// ────────────────────────────────────────────────────────────
// Signin handler tests
// ────────────────────────────────────────────────────────────
func TestSigninHandler_Success(t *testing.T) {
	mockSvc := new(mockAuthService)
	mockSvc.On("Signin", mock.Anything, "user@example.com", "123456").
		Return("mock-token", nil)

	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email: "user@example.com", Password: "123456",
	})
	req := httptest.NewRequest("POST", "/signin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockSvc.AssertExpectations(t)
}

func TestSigninHandler_WrongPassword(t *testing.T) {
	mockSvc := new(mockAuthService)
	mockSvc.On("Signin", mock.Anything, "user@example.com", "wrong").
		Return("", errors.New("incorrect password"))

	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email: "user@example.com", Password: "wrong",
	})
	req := httptest.NewRequest("POST", "/signin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	mockSvc.AssertExpectations(t)
}