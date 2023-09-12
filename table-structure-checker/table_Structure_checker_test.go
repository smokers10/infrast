package tablestructurechecker

import (
	"testing"

	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestLoginStructureChecker(t *testing.T) {
	mockRepository := contract.TableStructureCheckerRepositoryMock{Mock: mock.Mock{}}
	ch, err := config.ConfigurationHead("dummy_config/login.yaml")
	assert.NoError(t, err)
	checker := TableStructureChecker(&mockRepository)

	t.Run("mismatch", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{
				Field: "mismatch",
			},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, false).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&ch.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("match", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{
				Field: "token",
			},
			{
				Field: "failed_attempt",
			},
			{
				Field: "user_type",
			},
			{
				Field: "credential",
			},
			{
				Field: "login_at",
			},
			{
				Field: "device_id",
			},
			{
				Field: "attempt_at",
			},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, false).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&ch.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.Empty(t, result)
	})
}

func TestRegistrationStructureChecker(t *testing.T) {
	mockRepository := contract.TableStructureCheckerRepositoryMock{Mock: mock.Mock{}}
	ch, err := config.ConfigurationHead("dummy_config/registration.yaml")
	assert.NoError(t, err)
	checker := TableStructureChecker(&mockRepository)

	t.Run("mismatch", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{
				Field: "mismatch",
			},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, false).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&ch.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("match", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{Field: "id"},
			{Field: "credential"},
			{Field: "token"},
			{Field: "otp"},
			{Field: "status"},
			{Field: "device_id"},
			{Field: "created_at"},
			{Field: "user_type"},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, false).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&ch.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.Empty(t, result)
	})
}

func TestResetPasswordStructureChecker(t *testing.T) {
	mockRepository := contract.TableStructureCheckerRepositoryMock{Mock: mock.Mock{}}
	ch, err := config.ConfigurationHead("dummy_config/reset_password.yaml")
	assert.NoError(t, err)
	checker := TableStructureChecker(&mockRepository)

	t.Run("mismatch", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{
				Field: "mismatch",
			},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, false).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&ch.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("match", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{Field: "id"},
			{Field: "token"},
			{Field: "otp"},
			{Field: "credential"},
			{Field: "created_at"},
			{Field: "user_type"},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, false).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&ch.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.Empty(t, result)
	})
}

func TestUserCredentialStructureChecker(t *testing.T) {
	mockRepository := contract.TableStructureCheckerRepositoryMock{Mock: mock.Mock{}}
	configuration, err := config.ConfigurationHead("dummy_config/user_credential.yaml")
	assert.NoError(t, err)
	checker := TableStructureChecker(&mockRepository)

	t.Run("mismatch", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{
				Field: "mismatch",
			},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, true).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&configuration.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("match", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{Field: "id"},
			{Field: "profile"},
			{Field: "password"},
			{Field: "username"},
			{Field: "email"},
			{Field: "phone"},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, true).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&configuration.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.Empty(t, result)
	})
}

func TestUserFCMTokenStructureChecker(t *testing.T) {
	mockRepository := contract.TableStructureCheckerRepositoryMock{Mock: mock.Mock{}}
	configuration, err := config.ConfigurationHead("dummy_config/user_fcm_token.yaml")
	assert.NoError(t, err)
	checker := TableStructureChecker(&mockRepository)

	t.Run("mismatch", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{
				Field: "mismatch",
			},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, false).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&configuration.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("match", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{Field: "id"},
			{Field: "token"},
			{Field: "timestamp"},
			{Field: "user_type"},
			{Field: "user_id"},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, false).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&configuration.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.Empty(t, result)
	})
}

func TestUserDeviceChecker(t *testing.T) {
	mockRepository := contract.TableStructureCheckerRepositoryMock{Mock: mock.Mock{}}
	ch, err := config.ConfigurationHead("dummy_config/user_device.yaml")
	assert.NoError(t, err)
	checker := TableStructureChecker(&mockRepository)

	t.Run("mismatch", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{
				Field: "mismatch",
			},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, false).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&ch.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("match", func(t *testing.T) {
		columnsMatch := []contract.Column{
			{Field: "id"},
			{Field: "device_id"},
			{Field: "user_id"},
			{Field: "user_type"},
		}
		mockRepository.Mock.On("StructureGetter", mock.Anything, false).Return(columnsMatch, nil).Once()

		result, err := checker.StructureChecker(&ch.Configuration.UserManagement)
		assert.NoError(t, err)
		assert.Empty(t, result)
	})
}
