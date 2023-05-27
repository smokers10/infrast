package jsonwebtoken

import (
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/smokers10/go-infrastructure/config"
	"github.com/smokers10/go-infrastructure/contract"
)

type jsonwebtokenImplementation struct {
	Config *config.Configuration
}

// ParseToken implements contract.JsonWebTokenContract
func (i *jsonwebtokenImplementation) ParseToken(tokenString string) (payload map[string]interface{}, failure error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(i.Config.Application.Secret), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return map[string]interface{}{}, err
}

// Sign implements contract.JsonWebTokenContract
func (i *jsonwebtokenImplementation) Sign(payload map[string]interface{}) (token string, failure error) {
	var covertedPayload jwt.MapClaims

	bytePayload, _ := json.Marshal(payload)
	json.Unmarshal(bytePayload, &covertedPayload)

	tokenResult := jwt.NewWithClaims(jwt.SigningMethodHS256, covertedPayload)
	tokenString, err := tokenResult.SignedString([]byte(i.Config.Application.Secret))
	return tokenString, err
}

func JsonWebToken(Config *config.Configuration) contract.JsonWebTokenContract {
	return &jsonwebtokenImplementation{Config}
}
