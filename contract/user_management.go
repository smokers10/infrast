package contract

import (
	"github.com/stretchr/testify/mock"
)

type UserModel struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	PhotoProfile string `json:"photo_profile"`
	PhoneNumber  string `json:"phone_number"`
}

type ForgotPasswordModel struct {
	ID         int
	Token      string
	OTP        string
	Credential string
	CreatedAt  int64
	Type       string
}

type RegistrationModel struct {
	ID                 int
	Token              string
	OTP                string
	Credential         string
	CreatedAt          int64
	Type               string
	RegistrationStatus string
	DeviceID           string
}

type LoginModel struct {
	ID            int
	Token         string
	Credential    string
	Type          string
	DeviceID      string
	LoginAt       int64
	AttemptAt     int64
	FailedCounter int
}

type UserDeviceModel struct {
	ID       int
	DeviceID string
	UserID   int
	UserType string
}

type DynamicColumnValue struct {
	Column string
	Value  []string
}

type UserManagement interface {
	Login(credential string, password string, device_id string) (user *UserModel, token string, HTTPStatus int, failure error)

	RegisterNewAccount(credential string, device_id string) (token string, HTTPStatus int, failure error)

	RegisterVerification(token string, otp string) (HTTPStatus int, failure error)

	RegistrationBioData(credential string, query *DynamicColumnValue) (user *UserModel, tokens string, HTTPStatus int, failure error)

	ForgotPassword(credentials string) (tokens string, HTTPStatus int, failure error)

	ResetPassword(token string, otp string, new_password string, conf_password string) (HTTPStatus int, failure error)

	Logout(device_id string) (httpStatus int, failure error)
}

type UserManagementMock struct {
	Mock mock.Mock
}

func (m *UserManagementMock) Login(credential string, password string, device_id string) (user *UserModel, token string, HTTPStatus int, failure error) {
	args := m.Mock.Called(credential, password)
	return args.Get(0).(*UserModel), args.String(1), args.Int(2), args.Error(3)
}

func (m *UserManagementMock) RegisterNewAccount(credential string, device_id string) (token string, HTTPStatus int, failure error) {
	args := m.Mock.Called(credential)
	return args.String(0), args.Int(1), args.Error(2)
}

func (m *UserManagementMock) RegisterVerification(token string, otp string) (HTTPStatus int, failure error) {
	args := m.Mock.Called(token, otp)
	return args.Int(0), args.Error(1)
}

func (m *UserManagementMock) RegistrationBioData(credential string, query *DynamicColumnValue) (user *UserModel, tokens string, HTTPStatus int, failure error) {
	argsMock := m.Mock.Called(credential, query)
	return argsMock.Get(0).(*UserModel), argsMock.String(1), argsMock.Int(2), argsMock.Error(3)
}

func (m *UserManagementMock) ForgotPassword(credentials string) (tokens string, HTTPStatus int, failure error) {
	args := m.Mock.Called(credentials)
	return args.String(0), args.Int(1), args.Error(2)
}

func (m *UserManagementMock) ResetPassword(token string, otp string, new_password string, conf_password string) (HTTPStatus int, failure error) {
	args := m.Mock.Called(token, otp, new_password, conf_password)
	return args.Int(0), args.Error(1)
}

func (m *UserManagementMock) Logout(device_id string) (httpStatus int, failure error) {
	args := m.Mock.Called(device_id)
	return args.Int(9), args.Error(1)
}
