package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReader(t *testing.T) {
	c, err := ConfigurationHead("configuration.yaml")
	if err != nil {
		t.Fatalf("error config reader : %v\n", err.Error())
	}

	t.Run("check resgitered user type list", func(t *testing.T) {
		RUTL, err := c.RegisteredUserType()
		assert.Empty(t, err)
		for _, v := range RUTL {
			t.Logf("registered user : %s", v)
		}
	})

	t.Run("application", func(t *testing.T) {
		app := c.Configuration.Application
		assert.NotEmpty(t, app.Port)
		assert.NotEmpty(t, app.Secret)
		assert.NotEmpty(t, app.UserManagementPGInstance)
		t.Logf("umpginstace : %s", app.UserManagementPGInstance)
	})

	t.Run("postgres", func(t *testing.T) {
		postgres := c.Configuration.PostgreSQL
		for _, v := range postgres {
			t.Logf("testing pg instance : %s", v.Label)
			assert.NotEmpty(t, v.Label)
			assert.NotEmpty(t, v.ConnectionMaxLifeTime)
			assert.NotEmpty(t, v.DBName)
			assert.NotEmpty(t, v.Host)
			assert.NotEmpty(t, v.MaxIdleConnections)
			assert.NotEmpty(t, v.MaxOpenConnections)
			assert.NotEmpty(t, v.Password)
			assert.NotEmpty(t, v.Port)
			assert.NotEmpty(t, v.User)
		}
	})

	t.Run("mongodb", func(t *testing.T) {
		mongodb := c.Configuration.MongoDB
		for _, v := range mongodb {
			assert.NotEmpty(t, v.Label)
			assert.NotEmpty(t, v.DBName)
			assert.NotEmpty(t, v.MaxIdleConnections)
			assert.NotEmpty(t, v.MaxPool)
			assert.NotEmpty(t, v.MinPool)
			assert.NotEmpty(t, v.URI)
		}
	})

	t.Run("smtp", func(t *testing.T) {
		smtp := c.Configuration.SMTP
		assert.NotEmpty(t, smtp.Host)
		assert.NotEmpty(t, smtp.Password)
		assert.NotEmpty(t, smtp.Username)
		assert.NotEmpty(t, smtp.Port)
		assert.NotEmpty(t, smtp.Sender)
	})

	t.Run("midtrans", func(t *testing.T) {
		midtrans := c.Configuration.Midtrans
		assert.NotEmpty(t, midtrans.ServerKey)
		assert.NotEmpty(t, midtrans.EnabledPayments)
		assert.NotEmpty(t, midtrans.IrisKey)
		assert.NotEmpty(t, midtrans.Environment)
		for idx, v := range midtrans.EnabledPayments {
			t.Logf("index %v : %v\n", idx+1, v)
		}
	})

	t.Run("whatsapp", func(t *testing.T) {
		whatsapp := c.Configuration.Whatsapp
		assert.NotEmpty(t, whatsapp.SID)
		assert.NotEmpty(t, whatsapp.AuthToken)
		assert.NotEmpty(t, whatsapp.Sender)
	})

	t.Run("firebase", func(t *testing.T) {
		firebase := c.Configuration.Firebase
		assert.NotEmpty(t, firebase.ServiceAccountKey)
	})

	t.Run("user management", func(t *testing.T) {
		c := c.Configuration.UserManagement
		assert.NotEmpty(t, c.Users)
		assert.NotEmpty(t, c.Login)
		assert.NotEmpty(t, c.Registration)
		assert.NotEmpty(t, c.ResetPassword)
		t.Run("user check", func(t *testing.T) {
			t.Logf("user length : %v", len(c.Users))
			for _, v := range c.Users {
				assert.NotEmpty(t, v.IDProperty)
				assert.NotEmpty(t, v.PhotoProfileProperty)
				assert.NotEmpty(t, v.Credential)
				assert.NotEmpty(t, v.Type)
				assert.NotEmpty(t, v.UserTable)
				assert.NotEmpty(t, v.PasswordProperty)
				assert.NotEmpty(t, v.UsernameProperty)
				assert.NotEmpty(t, v.EmailProperty)
				assert.NotEmpty(t, v.PhoneProperty)
			}
		})

		t.Run("Login Check", func(t *testing.T) {
			assert.NotEmpty(t, c.Login.CredentialProperty)
			assert.NotEmpty(t, c.Login.FailedCounterProperty)
			assert.NotEmpty(t, c.Login.LoginAtProperty)
			assert.NotEmpty(t, c.Login.MaxFailedAttempt)
			assert.NotEmpty(t, c.Login.TableName)
			assert.NotEmpty(t, c.Login.TokenProperty)
			assert.NotEmpty(t, c.Login.TypeProperty)
			assert.NotEmpty(t, c.Login.DeviceIDProperty)
			assert.NotEmpty(t, c.Login.LoginBlockDuration)
			assert.NotEmpty(t, c.Login.AttemptAtProperty)
		})

		t.Run("Registration Check", func(t *testing.T) {
			assert.NotEmpty(t, c.Registration.TokenProperty)
			assert.NotEmpty(t, c.Registration.OTPProperty)
			assert.NotEmpty(t, c.Registration.TableName)
			assert.NotEmpty(t, c.Registration.CredentialProperty)
			assert.NotEmpty(t, c.Registration.RegistrationStatusProperty)
			assert.NotEmpty(t, c.Registration.DeviceIDProperty)
			assert.NotEmpty(t, c.Registration.UserTypeProperty)
			assert.NotEmpty(t, c.Registration.IDProperty)
			assert.NotEmpty(t, c.Registration.CreatedAtProperty)
			assert.NotEmpty(t, c.Registration.FCMTokenProperty)
		})

		t.Run("Reset Password Check", func(t *testing.T) {
			assert.NotEmpty(t, c.ResetPassword.CreatedAtProperty)
			assert.NotEmpty(t, c.ResetPassword.OTPProperty)
			assert.NotEmpty(t, c.ResetPassword.TableName)
			assert.NotEmpty(t, c.ResetPassword.TokenProperty)
			assert.NotEmpty(t, c.ResetPassword.ValidityDuration)
			assert.NotEmpty(t, c.ResetPassword.IDProperty)
			assert.NotEmpty(t, c.ResetPassword.UserTypeProperty)
			assert.NotEmpty(t, c.ResetPassword.CredentialProperty)
		})

		t.Run("User Device Check", func(t *testing.T) {
			assert.NotEmpty(t, c.UserDevice.DeviceIDProperty)
			assert.NotEmpty(t, c.UserDevice.IDProperty)
			assert.NotEmpty(t, c.UserDevice.TableName)
			assert.NotEmpty(t, c.UserDevice.UserIDProperty)
			assert.NotEmpty(t, c.UserDevice.UserTypeProperty)
		})

		t.Run("User FCM token", func(t *testing.T) {
			assert.NotEmpty(t, c.UserFCMToken.IDProperty)
			assert.NotEmpty(t, c.UserFCMToken.TableName)
			assert.NotEmpty(t, c.UserFCMToken.TimestampProperty)
			assert.NotEmpty(t, c.UserFCMToken.TokenProperty)
			assert.NotEmpty(t, c.UserFCMToken.UserTypeProperty)
			assert.NotEmpty(t, c.UserFCMToken.UserIDProperty)
		})

		t.Run("Message Template", func(t *testing.T) {
			c := c.MessageTemplate
			assert.NotEmpty(t, c.ForgotPasswordEmailTemplatePath)
			assert.NotEmpty(t, c.ForgotPasswordMessageTemplate)
			assert.NotEmpty(t, c.NewDeviceWarningEmailTemplatePath)
			assert.NotEmpty(t, c.NewDeviceWarningMessageTemplate)
			assert.NotEmpty(t, c.NewRegistrationEmailTemplatePath)
			assert.NotEmpty(t, c.NewRegistrationMessageTemplate)
			assert.NotEmpty(t, c.LoginCancelationURL)
			t.Logf("new registration email path : %v", c.NewRegistrationEmailTemplatePath)
			t.Logf("new device email path : %v", c.NewDeviceWarningEmailTemplatePath)
			t.Logf("forgot password email path: %v", c.ForgotPasswordEmailTemplatePath)
			t.Logf("new registration template message : %v", fmt.Sprintf(c.NewRegistrationMessageTemplate, "ABC123"))
			t.Logf("new device template message : %v", fmt.Sprintf(c.NewDeviceWarningMessageTemplate, "https://yousecureweb.com/cancel-login/<user-id>/<device-id>"))
			t.Logf("forgot password message : %v", fmt.Sprintf(c.ForgotPasswordMessageTemplate, "ABC456"))
		})
	})
}
