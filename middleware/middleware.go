package middleware

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
)

type MiddlewareImpl struct {
	Repository contract.UserManagementRepository
	JWT        contract.JsonWebTokenContract
	UMC        *config.UserManagementConfig
}

// GetRequiredHeaderX to reader request header that required such as token and user device id
func (*MiddlewareImpl) GetRequiredHeaderX(tokenXHeader string, DeviceIDXHeader string, c *fiber.Ctx) (token string, deviceID string) {
	token = c.Get(tokenXHeader)
	deviceID = c.Get(DeviceIDXHeader)

	return token, deviceID
}

// Authenticate to authenticate user access
func (i *MiddlewareImpl) Authenticate(token string, device_id string) (*contract.MiddlewareResponse, error) {
	if token == "" || device_id == "" {
		return &contract.MiddlewareResponse{
			Message:         "unauthenticated access",
			Status:          401,
			IsAuthenticated: false,
			Reason:          "required header is empty",
		}, fmt.Errorf("required header is empty (token & device id)")
	}

	// parse jwt token
	payload, err := i.JWT.ParseToken(token)
	if err != nil {
		return &contract.MiddlewareResponse{
			Message:         "authentication error",
			Status:          500,
			IsAuthenticated: false,
			Reason:          err.Error(),
		}, fmt.Errorf("error : %v", err.Error())
	}

	types := payload["type"].(string)
	userID := payload["user_id"].(int)

	// match the roles type from YAML with payload["type"]
	if i.UMC.SelectedCredential.Type != types {
		return &contract.MiddlewareResponse{
			Message:         "unauthorized access",
			Status:          401,
			IsAuthenticated: false,
			Reason:          fmt.Sprintf("type %s now allowed to access this end point", types),
		}, fmt.Errorf("error : %v", "unauthorized access")
	}

	// feth user device
	userDevice, err := i.Repository.FindUserDevice(i.UMC, userID, device_id)
	if err != nil {
		return &contract.MiddlewareResponse{
			Message:         "internal server error",
			Status:          500,
			IsAuthenticated: false,
			Reason:          err.Error(),
		}, fmt.Errorf("error find user device: %v", err.Error())
	}

	// if user device not exists
	if *userDevice == (contract.UserDeviceModel{}) {
		return &contract.MiddlewareResponse{
			Message:         "unauthorized access",
			Status:          http.StatusUnauthorized,
			IsAuthenticated: false,
			Reason:          fmt.Sprintf("device id %s not registered", device_id),
		}, fmt.Errorf("error : %v", fmt.Errorf("device id %s not registered", device_id))
	}

	// fetch login session
	loginSession, err := i.Repository.FindOneLoginSession(i.UMC, device_id)
	if err != nil {
		return &contract.MiddlewareResponse{
			Message:         "internal server error",
			Status:          500,
			IsAuthenticated: false,
			Reason:          err.Error(),
		}, fmt.Errorf("error find login session : %v", err.Error())
	}

	// if login not found
	if *loginSession == (contract.LoginModel{}) {
		return &contract.MiddlewareResponse{
			Message:         "unauthorized access",
			Status:          http.StatusUnauthorized,
			IsAuthenticated: false,
			Reason:          "login session not valid",
		}, errors.New("login session not valid")
	}

	// fetch user data
	user, err := i.Repository.FindOneUser(i.UMC, loginSession.Credential)
	if err != nil {
		return &contract.MiddlewareResponse{
			Message:         "internal server error",
			Status:          500,
			IsAuthenticated: false,
			Reason:          err.Error(),
		}, fmt.Errorf("error find one user : %v", err.Error())
	}

	// if user not found
	if *user == (contract.UserModel{}) {
		return &contract.MiddlewareResponse{
			Message:         "unauthorized access",
			Status:          http.StatusUnauthorized,
			IsAuthenticated: false,
			Reason:          "user not registered",
		}, errors.New("user not registered")
	}

	// return response
	return &contract.MiddlewareResponse{
		Message:         "access granted",
		Status:          200,
		IsAuthenticated: true,
		Claimer: struct {
			Id       int    "json:\"id\""
			DeviceID string "json:\"device_id\""
		}{
			Id:       userID,
			DeviceID: device_id,
		},
	}, nil
}

func Middleware(user_management_conf *config.UserManagementConfig, repository contract.UserManagementRepository, jwt contract.JsonWebTokenContract, user_type string) (contract.Middleware, error) {
	selectedUserCredential := config.UserCredential{}
	for _, v := range user_management_conf.UserCredential {
		if v.Type == user_type {
			selectedUserCredential = v
			break
		}
	}

	registeredUserType := []string{}
	for _, v := range user_management_conf.UserCredential {
		registeredUserType = append(registeredUserType, v.Type)
	}

	if selectedUserCredential.Type != user_type {
		return nil, fmt.Errorf("user type not registered, here registered user type : %v", registeredUserType)
	}

	user_management_conf.SelectedCredential = selectedUserCredential

	return &MiddlewareImpl{
		Repository: repository,
		JWT:        jwt,
		UMC:        user_management_conf,
	}, nil
}
