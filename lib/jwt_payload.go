package lib

import (
	"time"

	"github.com/smokers10/infrast/config"
)

type payloadData struct {
	Sub      int
	UserType string
	Iat      int64
	Eat      int64
}

func MakeJWTPayload(sub int, selectedCred config.UserManagementConfig) map[string]interface{} {
	return map[string]interface{}{
		"sub":  sub,
		"type": selectedCred.SelectedCredential.Type,
		"iat":  time.Now().UTC().Unix(),
		"eat":  time.Now().UTC().AddDate(0, 0, 10).Unix(),
	}
}

func ParsePayload(data map[string]interface{}) *payloadData {
	return &payloadData{
		Sub:      data["sub"].(int),
		UserType: data["type"].(string),
		Iat:      data["iat"].(int64),
		Eat:      data["eat"].(int64),
	}
}
