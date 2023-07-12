package midtrans

import (
	"testing"

	"github.com/smokers10/infrast/config"
	"github.com/stretchr/testify/assert"
)

func TestMidtrans(t *testing.T) {
	t.Run("error environment", func(t *testing.T) {
		c := config.Configuration{
			Midtrans: config.Midtrans{
				ServerKey:       "server-key",
				IrisKey:         "iris-key",
				Environment:     "testing",
				EnabledPayments: []string{"bri", "mandiri"},
			},
		}
		midtrans, err := Midtrans(&c)
		assert.Error(t, err)
		assert.Nil(t, midtrans)
		t.Logf("err : %v", err.Error())
	})

	t.Run("success define midtrans", func(t *testing.T) {
		c := config.Configuration{
			Midtrans: config.Midtrans{
				ServerKey:       "server-key",
				IrisKey:         "iris-key",
				Environment:     "sandbox",
				EnabledPayments: []string{"bri", "mandiri"},
			},
		}
		midtrans, err := Midtrans(&c)
		assert.NoError(t, err)
		assert.NotNil(t, midtrans)
	})
}
