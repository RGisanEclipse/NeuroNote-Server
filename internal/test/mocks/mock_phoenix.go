package mocks

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix"
	"github.com/stretchr/testify/mock"
)

type MockPhoenixService struct {
	mock.Mock
}

// SendMail mocks sending an email
func (m *MockPhoenixService) SendMail(ctx context.Context, userID string, template phoenix.EmailTemplate) error {
	args := m.Called(ctx, userID, template)
	return args.Error(0)
}
