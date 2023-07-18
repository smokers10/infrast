package contract

import (
	"github.com/stretchr/testify/mock"
)

type UserManagement interface {
	Login(credential string, password string, device_id string) (user *UserModel, token string, HTTPStatus int, failure error)

	RegisterNewAccount(credential string, device_id string, fcm_token string) (token string, HTTPStatus int, failure error)

	RegisterVerification(token string, otp string) (HTTPStatus int, failure error)

	CompleteRegistration(credential string, query *DynamicColumnValue) (user *UserModel, tokens string, HTTPStatus int, failure error)

	ForgotPassword(credentials string) (tokens string, HTTPStatus int, failure error)

	ResetPassword(token string, otp string, new_password string, conf_password string) (HTTPStatus int, failure error)

	Logout(device_id string) (httpStatus int, failure error)

	UpdateUserCredential(new_credential string, current_password string, user_id int, credential_property string) (HTTPStatus int, failure error)

	UpdateUserPassword(new_password string, confirmation_password string, user_id int) (HTTPStatus int, failure error)

	UpsertUserFCMToken(token string, user_id int) (HTTPStatus int, failure error)

	UpdateUserJWTToken(user_id int, device_id string) (token string, HTTPStatus int, failure error)

	CheckUserJWTToken(device_id string) (checkResponse map[string]interface{}, HTTPStatus int, failure error)
}

type UserManagementMock struct {
	Mock mock.Mock
}

func (m *UserManagementMock) UpdateUserCredential(new_credential string, current_password string, credential_property string) (HTTPStatus int, failure error) {
	args := m.Mock.Called(new_credential, current_password, credential_property)
	return args.Int(0), args.Error(1)
}

func (m *UserManagementMock) UpdateUserPassword(new_password string, confirmation_password string) (HTTPStatus int, failure error) {
	args := m.Mock.Called(new_password, confirmation_password)
	return args.Int(0), args.Error(1)
}

func (m *UserManagementMock) UpsertUserFCMToken(token string, user_id int) (HTTPStatus int, failure error) {
	args := m.Mock.Called(token, user_id)
	return args.Int(0), args.Error(1)
}

func (m *UserManagementMock) UpdateUserJWTToken(user_id int, device_id string) (token string, HTTPStatus int, failure error) {
	args := m.Mock.Called(device_id, user_id)
	return args.String(0), args.Int(1), args.Error(2)
}

func (m *UserManagementMock) CheckUserJWTToken(device_id string) (checkResponse map[string]interface{}, HTTPStatus int, failure error) {
	args := m.Mock.Called(device_id)
	return args.Get(0).(map[string]interface{}), args.Int(1), args.Error(2)
}

func (m *UserManagementMock) Login(credential string, password string, device_id string) (user *UserModel, token string, HTTPStatus int, failure error) {
	args := m.Mock.Called(credential, password)
	return args.Get(0).(*UserModel), args.String(1), args.Int(2), args.Error(3)
}

func (m *UserManagementMock) RegisterNewAccount(credential string, device_id string, fcm_token string) (token string, HTTPStatus int, failure error) {
	args := m.Mock.Called(credential, device_id, fcm_token)
	return args.String(0), args.Int(1), args.Error(2)
}

func (m *UserManagementMock) RegisterVerification(token string, otp string) (HTTPStatus int, failure error) {
	args := m.Mock.Called(token, otp)
	return args.Int(0), args.Error(1)
}

func (m *UserManagementMock) CompleteRegistration(credential string, query *DynamicColumnValue) (user *UserModel, tokens string, HTTPStatus int, failure error) {
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
