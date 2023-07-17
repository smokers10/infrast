package templateprocessor

import (
	"testing"
	"time"
)

type table struct {
	Label string
	Path  string
	Data  map[string]interface{}
}

func TestEmailTemplate(t *testing.T) {
	TP := TemplateProccessor()
	tt := []table{
		{
			Label: "forgot password email template processing",
			Path:  "forgot_password.html",
			Data: map[string]interface{}{
				"issuer_name": "Ferani F. Ramadhani",
				"otp":         "ABC123",
			},
		},
		{
			Label: "new account template processing",
			Path:  "new_account_registration.html",
			Data: map[string]interface{}{
				"otp": "ABC123",
			},
		},
		{
			Label: "new device template processing",
			Path:  "new_device_warning.html",
			Data: map[string]interface{}{
				"logout_url": "https://yoursafeBE.com/cancel-login/<device-id>/<user-id>",
				"logged_at":  time.Now().UTC().Local().Format("2006-01-02 3:4 pm"),
			},
		},
	}

	for _, v := range tt {
		t.Run(v.Label, func(t *testing.T) {
			result, err := TP.EmailTemplate(v.Data, v.Path)
			if err != nil {
				t.Fatalf("error : %v/n", err)
			}

			t.Log(result)
		})
	}
}
