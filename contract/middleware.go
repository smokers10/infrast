package contract

import (
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
)

type MiddlewareResponse struct {
	Message         string `json:"message,omitempty"`
	Status          int    `json:"status,omitempty"`
	IsAuthenticated bool   `json:"omitempty"`
	Reason          string `json:"reason,omitempty"`
	Claimer         struct {
		Id       int    `json:"id"`
		DeviceID string `json:"device_id"`
	}
}

type Middleware interface {
	Authenticate(token string, deviceID string) (*MiddlewareResponse, error)

	GetRequiredHeaderX(tokenXHeader string, DeviceIDXHeader string, c *fiber.Ctx) (token string, deviceID string)
}

type MiddlewareMock struct {
	Mock mock.Mock
}

func (m *MiddlewareMock) Authenticate(token string, deviceID string) (*MiddlewareResponse, error) {
	args := m.Mock.Called(token, deviceID)
	return args.Get(0).(*MiddlewareResponse), args.Error(1)
}

func (m *MiddlewareMock) GetRequiredHeaderX(tokenXHeader string, DeviceIDXHeader string, c *fiber.Ctx) (token string, deviceID string) {
	args := m.Mock.Called(tokenXHeader, DeviceIDXHeader)
	return args.String(0), args.String(1)
}
