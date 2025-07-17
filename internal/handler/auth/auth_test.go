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
	authErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/auth"
)

// Mock service that satisfies authservice.Service
type mockAuthService struct{ mock.Mock }

func (m *mockAuthService) Signup(ctx context.Context, email, pw string) (uint,string, error) {
	args := m.Called(ctx, email, pw)
	return  args.Get(0).(uint), args.String(1), args.Error(2)
}
func (m *mockAuthService) Signin(ctx context.Context, email, pw string) (uint, string, error) {
	args := m.Called(ctx, email, pw)
	return  args.Get(0).(uint), args.String(1), args.Error(2)
}

// Signup handler tests
func TestSignupHandler_Success(t *testing.T) {
	mockSvc := new(mockAuthService)
	mockSvc.On("Signup", mock.Anything, "test@example.com", "validPass@1234").
		Return(uint(123), "mock-token", nil)

	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email: "test@example.com", Password: "validPass@1234",
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
	mockSvc.On("Signup", mock.Anything, "exists@example.com", "validPass@1234").
		Return(uint(0), "", errors.New("email already exists"))

	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email: "exists@example.com", Password: "validPass@1234",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var res authmodel.AuthResponse
	err := json.Unmarshal(rec.Body.Bytes(), &res)
	assert.NoError(t, err)
	assert.False(t, res.Success)
	assert.Equal(t, authErr.AuthError.EmailExists, res.Message)
	mockSvc.AssertExpectations(t)
}

func TestSignupHandler_BadRequest(t *testing.T) {
	mockSvc := new(mockAuthService)

	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	tests := []struct {
		name       string
		request    authmodel.AuthRequest
	}{
		{
			name:    "MissingEmail",
			request: authmodel.AuthRequest{Password: "123456"},
		},
		{
			name:    "MissingPassword",
			request: authmodel.AuthRequest{Email: "user@example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.request)

			req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			mockSvc.AssertNotCalled(t, "Signup")
		})
	}
}

func TestSignupHandler_MissingEmail(t *testing.T) {
	mockSvc := new(mockAuthService)
	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Password: "ValidPass@123",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp authmodel.AuthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	assert.False(t, resp.Success)
	assert.Equal(t, authErr.AuthError.EmailRequired, resp.Message)

	mockSvc.AssertNotCalled(t, "Signup")
}

func TestSignupHandler_InvalidEmailFormat(t *testing.T) {
	mockSvc := new(mockAuthService)
	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email:    "invalidemail.com",
		Password: "ValidPass@123",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp authmodel.AuthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	assert.False(t, resp.Success)
	assert.Equal(t, authErr.AuthError.InvalidEmail, resp.Message)

	mockSvc.AssertNotCalled(t, "Signup")
}

func TestSignupHandler_MissingPassword(t *testing.T) {
	mockSvc := new(mockAuthService)
	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email: "a@b.com",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp authmodel.AuthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	assert.False(t, resp.Success)
	assert.Equal(t, authErr.AuthError.PasswordRequired, resp.Message)

	mockSvc.AssertNotCalled(t, "Signup")
}


func TestSignupHandler_ShortPassword(t *testing.T) {
	mockSvc := new(mockAuthService)
	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email:    "a@b.com",
		Password: "123456",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp authmodel.AuthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	assert.False(t, resp.Success)
	assert.Equal(t, authErr.AuthError.PasswordTooShort, resp.Message)

	mockSvc.AssertNotCalled(t, "Signup")
}

func TestSignupHandler_LongPassword(t *testing.T) {
	mockSvc := new(mockAuthService)
	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	longPass := "VeryLongPasswordWithAllComponents@12345678999999999999"
	body, _ := json.Marshal(authmodel.AuthRequest{
		Email:    "a@b.com",
		Password: longPass,
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp authmodel.AuthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	assert.False(t, resp.Success)
	assert.Equal(t, authErr.AuthError.PasswordTooLong, resp.Message)

	mockSvc.AssertNotCalled(t, "Signup")
}

func TestSignupHandler_PasswordWithoutUppercase(t *testing.T) {
	mockSvc := new(mockAuthService)
	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email:    "a@b.com",
		Password: "lowercase@123",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp authmodel.AuthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	assert.False(t, resp.Success)
	assert.Equal(t, authErr.AuthError.PasswordMissingUppercase, resp.Message)

	mockSvc.AssertNotCalled(t, "Signup")
}

func TestSignupHandler_PasswordWithoutLowercase(t *testing.T) {
	mockSvc := new(mockAuthService)
	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email:    "a@b.com",
		Password: "UPPERCASE@123",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp authmodel.AuthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	assert.False(t, resp.Success)
	assert.Equal(t, authErr.AuthError.PasswordMissingLowercase, resp.Message)

	mockSvc.AssertNotCalled(t, "Signup")
}

func TestSignupHandler_PasswordWithoutDigit(t *testing.T) {
	mockSvc := new(mockAuthService)
	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email:    "a@b.com",
		Password: "Password@",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp authmodel.AuthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	assert.False(t, resp.Success)
	assert.Equal(t, authErr.AuthError.PasswordMissingDigit, resp.Message)

	mockSvc.AssertNotCalled(t, "Signup")
}

func TestSignupHandler_PasswordWithoutSpecialChar(t *testing.T) {
	mockSvc := new(mockAuthService)
	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email:    "a@b.com",
		Password: "Password123",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp authmodel.AuthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	assert.False(t, resp.Success)
	assert.Equal(t, authErr.AuthError.PasswordMissingSpecialCharacter, resp.Message)

	mockSvc.AssertNotCalled(t, "Signup")
}

func TestSignupHandler_PasswordWithWhitespace(t *testing.T) {
	mockSvc := new(mockAuthService)
	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email:    "a@b.com",
		Password: "Valid Pass@123",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp authmodel.AuthResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	assert.NoError(t, err)

	assert.False(t, resp.Success)
	assert.Equal(t, authErr.AuthError.PasswordContainsWhitespace, resp.Message)

	mockSvc.AssertNotCalled(t, "Signup")
}

// Signin handler tests

func TestSigninHandler_Success(t *testing.T) {
	mockSvc := new(mockAuthService)
	mockSvc.On("Signin", mock.Anything, "user@example.com", "123456").
		Return(uint(123), "mock-token", nil)

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
		Return(uint(0), "", errors.New(authErr.AuthError.IncorrectPassword))

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

	var res authmodel.AuthResponse
	err := json.Unmarshal(rec.Body.Bytes(), &res)
	assert.NoError(t, err)
	assert.False(t, res.Success)
	assert.Equal(t, authErr.AuthError.IncorrectPassword, res.Message)

	mockSvc.AssertExpectations(t)
}

func TestSigninHandler_EmailDoesNotExist(t *testing.T) {
	mockSvc := new(mockAuthService)
	mockSvc.On("Signin", mock.Anything, "ghost@example.com", "123456").
		Return(uint(0), "", errors.New(authErr.AuthError.EmailDoesntExist))

	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, mockSvc)

	body, _ := json.Marshal(authmodel.AuthRequest{
		Email: "ghost@example.com", Password: "123456",
	})
	req := httptest.NewRequest("POST", "/signin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var res authmodel.AuthResponse
	err := json.Unmarshal(rec.Body.Bytes(), &res)
	assert.NoError(t, err)
	assert.False(t, res.Success)
	assert.Equal(t, authErr.AuthError.EmailDoesntExist, res.Message)

	mockSvc.AssertExpectations(t)
}