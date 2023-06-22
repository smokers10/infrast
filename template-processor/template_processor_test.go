package templateprocessor

import (
	"testing"

	"github.com/smokers10/go-infrastructure/config"
)

func TestEmailTemplate(t *testing.T) {
	c := config.Configuration{
		UserManagement: config.UserManagementConfig{
			ResetPassword: config.ResetPasswordConfig{
				EmailTemplatePath: "testing.html",
			},
		},
	}
	TP := TemplateProccessor()
	data := map[string]interface{}{
		"reciever": "Jane Doe",
		"otp":      "this-is-otp",
	}

	t.Run("check process", func(t *testing.T) {
		result, err := TP.EmailTemplate(data, c.UserManagement.ResetPassword.EmailTemplatePath)
		if err != nil {
			t.Fatalf("error : %v/n", err)
		}

		t.Log(result)
	})
}
