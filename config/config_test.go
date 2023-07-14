package config

import (
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
	})

	t.Run("postgres", func(t *testing.T) {
		postgres := c.Configuration.PostgreSQL
		assert.NotEmpty(t, postgres.ConnectionMaxLifeTime)
		assert.NotEmpty(t, postgres.DBName)
		assert.NotEmpty(t, postgres.Host)
		assert.NotEmpty(t, postgres.MaxIdleConnections)
		assert.NotEmpty(t, postgres.MaxOpenConnections)
		assert.NotEmpty(t, postgres.Password)
		assert.NotEmpty(t, postgres.Port)
		assert.NotEmpty(t, postgres.User)
	})

	t.Run("mongodb", func(t *testing.T) {
		mongodb := c.Configuration.MongoDB
		assert.NotEmpty(t, mongodb.DBName)
		assert.NotEmpty(t, mongodb.MaxIdleConnections)
		assert.NotEmpty(t, mongodb.MaxPool)
		assert.NotEmpty(t, mongodb.MinPool)
		assert.NotEmpty(t, mongodb.URI)
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
		assert.NotEmpty(t, c.UserCredential)
		assert.NotEmpty(t, c.Login)
		assert.NotEmpty(t, c.Registration)
		assert.NotEmpty(t, c.ResetPassword)
		t.Run("user credential check", func(t *testing.T) {
			t.Logf("user credential length : %v", len(c.UserCredential))
			for _, v := range c.UserCredential {
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
			assert.NotEmpty(t, c.Login.EmailTemplatePath)
		})

		t.Run("Registration Check", func(t *testing.T) {
			assert.NotEmpty(t, c.Registration.TokenProperty)
			assert.NotEmpty(t, c.Registration.OTPProperty)
			assert.NotEmpty(t, c.Registration.TableName)
			assert.NotEmpty(t, c.Registration.CredentialProperty)
			assert.NotEmpty(t, c.Registration.RegistrationStatusProperty)
			assert.NotEmpty(t, c.Registration.EmailTemplatePath)
			assert.NotEmpty(t, c.Registration.DeviceIDProperty)
			assert.NotEmpty(t, c.Registration.UserTypeProperty)
			assert.NotEmpty(t, c.Registration.IDProperty)
			assert.NotEmpty(t, c.Registration.CreatedAtProperty)
		})

		t.Run("Reset Password Check", func(t *testing.T) {
			assert.NotEmpty(t, c.ResetPassword.CreatedAtProperty)
			assert.NotEmpty(t, c.ResetPassword.OTPProperty)
			assert.NotEmpty(t, c.ResetPassword.TableName)
			assert.NotEmpty(t, c.ResetPassword.TokenProperty)
			assert.NotEmpty(t, c.ResetPassword.ValidityDuration)
			assert.NotEmpty(t, c.ResetPassword.EmailTemplatePath)
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
			assert.NotEmpty(t, c.UserDevice.EmailTemplatePath)
		})

		t.Run("User FCM token", func(t *testing.T) {
			assert.NotEmpty(t, c.UserFCMToken.IDProperty)
			assert.NotEmpty(t, c.UserFCMToken.TableName)
			assert.NotEmpty(t, c.UserFCMToken.TimestampProperty)
			assert.NotEmpty(t, c.UserFCMToken.TokenProperty)
			assert.NotEmpty(t, c.UserFCMToken.UserTypeProperty)
		})
	})
}
