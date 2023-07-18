package contract

import (
	"github.com/smokers10/infrast/config"
	"github.com/stretchr/testify/mock"
)

type UserManagementRepository interface {
	GetUserCredentials(umc *config.UserManagementConfig, user_id int) (*UserModel, error)

	FindOneUser(umc *config.UserManagementConfig, credential string) (*UserModel, error)

	FindOneUserByID(umc *config.UserManagementConfig, user_id int) (*UserModel, error)

	CreateRegistration(umc *config.UserManagementConfig, token string, credential string, otp string, device_id string, fcm_token string, created_at int64) error

	FindOneRegistration(umc *config.UserManagementConfig, token string) (*RegistrationModel, error)

	FindOneRegistrationByCredential(umc *config.UserManagementConfig, credential string) (*RegistrationModel, error)

	UpdateRegistration(umc *config.UserManagementConfig, token string, credential string, otp string, device_id string, fcm_token string, created_at int64) error

	UpdateStatusRegistration(umc *config.UserManagementConfig, token string) error

	StoreUser(umc *config.UserManagementConfig, column string, args ...string) (int, error)

	UpdateUserPassword(umc *config.UserManagementConfig, credential string, safe_password string) error

	StoreForgotPassword(umc *config.UserManagementConfig, credential string, token string, otp string) error

	FindOneForgotPassword(umc *config.UserManagementConfig, token string) (*ForgotPasswordModel, error)

	DeleteForgotPassword(umc *config.UserManagementConfig, token string) error

	UpdateLoginFailedAttempt(umc *config.UserManagementConfig, device_id string, new_number int) error

	UpdateLoginCredential(umc *config.UserManagementConfig, device_id string, credential string) error

	CreateNewLoginSession(umc *config.UserManagementConfig, credential string, device_id string) error

	FindOneLoginSession(umc *config.UserManagementConfig, device_id string) (*LoginModel, error)

	CompleteLoginSession(umc *config.UserManagementConfig, token string, device_id string, login_at int64) error

	DeleteLoginSession(umc *config.UserManagementConfig, device_id string) error

	CreateCompleteLoginSession(umc *config.UserManagementConfig, token string, credential string, device_id string, login_at int64) error

	CreateNewUserDevice(umc *config.UserManagementConfig, user_id int, device_id string) error

	FindUserDevice(umc *config.UserManagementConfig, user_id int, device_id string) (*UserDeviceModel, error)

	UpdateCredential(umc *config.UserManagementConfig, new_credential string, user_id int, credential_property string) error

	UpdateUserPasswordByUserID(umc *config.UserManagementConfig, new_password string, user_id int) error

	GetFCMToken(umc *config.UserManagementConfig, user_id int) (*UserFCMTokenModel, error)

	StoreFCMToken(umc *config.UserManagementConfig, token string, timestamp int64, user_id int) error

	UpdateFCMToken(umc *config.UserManagementConfig, token string, timestamp int64, user_id int) error

	UpdateJWTToken(umc *config.UserManagementConfig, token string, device_id string) error
}

type UserManagementRepositoryMock struct {
	Mock mock.Mock
}

func (m *UserManagementRepositoryMock) CreateCompleteLoginSession(umc *config.UserManagementConfig, token string, credential string, device_id string, login_at int64) error {
	args := m.Mock.Called(umc, token, credential, device_id, login_at)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) GetUserCredentials(umc *config.UserManagementConfig, user_id int) (*UserModel, error) {
	args := m.Mock.Called(umc, user_id)
	return args.Get(0).(*UserModel), args.Error(1)
}

func (m *UserManagementRepositoryMock) FindOneUserByID(umc *config.UserManagementConfig, user_id int) (*UserModel, error) {
	args := m.Mock.Called(umc, user_id)
	return args.Get(0).(*UserModel), args.Error(1)
}

func (m *UserManagementRepositoryMock) GetFCMToken(umc *config.UserManagementConfig, user_id int) (*UserFCMTokenModel, error) {
	args := m.Mock.Called(umc, user_id)
	return args.Get(0).(*UserFCMTokenModel), args.Error(1)
}

func (m *UserManagementRepositoryMock) UpdateCredential(umc *config.UserManagementConfig, new_credential string, user_id int, credential_property string) error {
	args := m.Mock.Called(umc, new_credential, credential_property, user_id)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) UpdateUserPasswordByUserID(umc *config.UserManagementConfig, new_password string, user_id int) error {
	args := m.Mock.Called(umc, new_password, user_id)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) StoreFCMToken(umc *config.UserManagementConfig, token string, timestamp int64, user_id int) error {
	args := m.Mock.Called(umc, token, timestamp, user_id)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) UpdateFCMToken(umc *config.UserManagementConfig, token string, timestamp int64, user_id int) error {
	args := m.Mock.Called(umc, token, timestamp, user_id)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) UpdateJWTToken(umc *config.UserManagementConfig, token string, device_id string) error {
	args := m.Mock.Called(umc, token, device_id)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) UpdateRegistration(user_management_conf *config.UserManagementConfig, token string, credential string, otp string, device_id string, fcm_token string, created_at int64) error {
	args := m.Mock.Called(user_management_conf, token, credential, otp, device_id, fcm_token, created_at)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) FindOneUser(user_management_conf *config.UserManagementConfig, credential string) (*UserModel, error) {
	args := m.Mock.Called(user_management_conf, credential)
	return args.Get(0).(*UserModel), args.Error(1)
}

func (m *UserManagementRepositoryMock) CreateRegistration(user_management_conf *config.UserManagementConfig, token string, credential string, otp string, device_id string, fcm_token string, created_at int64) error {
	args := m.Mock.Called(user_management_conf, token, credential, otp, device_id, fcm_token, created_at)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) FindOneRegistration(user_management_conf *config.UserManagementConfig, token string) (*RegistrationModel, error) {
	args := m.Mock.Called(user_management_conf, token)
	return args.Get(0).(*RegistrationModel), args.Error(1)
}

func (m *UserManagementRepositoryMock) FindOneRegistrationByCredential(user_management_conf *config.UserManagementConfig, credential string) (*RegistrationModel, error) {
	args := m.Mock.Called(user_management_conf, credential)
	return args.Get(0).(*RegistrationModel), args.Error(1)
}

func (m *UserManagementRepositoryMock) UpdateStatusRegistration(user_management_conf *config.UserManagementConfig, token string) error {
	args := m.Mock.Called(user_management_conf, token)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) StoreUser(user_management_conf *config.UserManagementConfig, column string, args ...string) (int, error) {
	argsMock := m.Mock.Called(user_management_conf, column, args)
	return argsMock.Int(0), argsMock.Error(1)
}

func (m *UserManagementRepositoryMock) UpdateUserPassword(user_management_conf *config.UserManagementConfig, credential string, safe_password string) error {
	args := m.Mock.Called(user_management_conf, credential, safe_password)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) StoreForgotPassword(user_management_conf *config.UserManagementConfig, credential string, token string, otp string) error {
	args := m.Mock.Called(user_management_conf, credential, token, otp)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) FindOneForgotPassword(user_management_conf *config.UserManagementConfig, token string) (*ForgotPasswordModel, error) {
	args := m.Mock.Called(user_management_conf, token)
	return args.Get(0).(*ForgotPasswordModel), args.Error(1)
}

func (m *UserManagementRepositoryMock) DeleteForgotPassword(user_management_conf *config.UserManagementConfig, token string) error {
	args := m.Mock.Called(user_management_conf, token)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) CreateNewLoginSession(user_management_conf *config.UserManagementConfig, credential string, device_id string) error {
	args := m.Mock.Called(user_management_conf, credential, device_id)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) FindOneLoginSession(userManagementConf *config.UserManagementConfig, deviceID string) (*LoginModel, error) {
	args := m.Mock.Called(userManagementConf, deviceID)
	return args.Get(0).(*LoginModel), args.Error(1)
}

func (m *UserManagementRepositoryMock) GetLoginFailedAttempt(userManagementConf *config.UserManagementConfig, deviceID string) (int, error) {
	args := m.Mock.Called(userManagementConf, deviceID)
	return args.Int(0), args.Error(1)
}

func (m *UserManagementRepositoryMock) UpdateLoginFailedAttempt(userManagementConf *config.UserManagementConfig, deviceID string, newNumber int) error {
	args := m.Mock.Called(userManagementConf, deviceID, newNumber)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) UpdateLoginCredential(userManagementConf *config.UserManagementConfig, deviceID string, credential string) error {
	args := m.Mock.Called(userManagementConf, deviceID, credential)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) CompleteLoginSession(userManagementConf *config.UserManagementConfig, token string, deviceID string, loginAt int64) error {
	args := m.Mock.Called(userManagementConf, token, deviceID, loginAt)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) DeleteLoginSession(user_management_conf *config.UserManagementConfig, device_id string) error {
	args := m.Mock.Called(user_management_conf, device_id)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) CreateNewUserDevice(user_management_conf *config.UserManagementConfig, user_id int, device_id string) error {
	args := m.Mock.Called(user_management_conf, user_id, device_id)
	return args.Error(0)
}

func (m *UserManagementRepositoryMock) FindUserDevice(user_management_conf *config.UserManagementConfig, user_id int, device_id string) (*UserDeviceModel, error) {
	args := m.Mock.Called(user_management_conf, user_id, device_id)
	return args.Get(0).(*UserDeviceModel), args.Error(1)
}
