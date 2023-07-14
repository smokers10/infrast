package firebase

import (
	"context"
	"encoding/base64"
	"errors"
	"log"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/messaging"
	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"google.golang.org/api/option"
)

type firebaseImpl struct {
	config *config.Firebase
	fcm    *messaging.Client
}

// SendMessage implements contract.Firebase.
func (i *firebaseImpl) SendMessage(data *messaging.Message) error {
	response, err := i.fcm.Send(context.Background(), data)
	if err != nil {
		return err
	}
	log.Printf("Response : %v", response)

	return nil
}

// SendMulticastMessage implements contract.Firebase.
func (i *firebaseImpl) SendMulticastMessage(data *messaging.MulticastMessage) error {
	response, err := i.fcm.SendMulticast(context.Background(), data)
	if err != nil {
		return err
	}
	log.Printf("Success count : %v", response.SuccessCount)
	log.Printf("Failure count : %v", response.FailureCount)
	for _, v := range response.Responses {
		log.Printf("is success : %v\nerror : %v\nmessage id : %v \n\n", v.Success, v.Error, v.MessageID)
	}

	return nil
}

func Firebase(config *config.Configuration) (contract.Firebase, error) {
	fconfig := config.Firebase

	if fconfig.ServiceAccountKey == "" {
		return nil, errors.New("unauthorized")
	}

	sak, err := getServiceAccountKey(fconfig.ServiceAccountKey)
	if err != nil {
		return nil, err
	}

	opts := option.WithCredentialsJSON(sak)

	app, err := firebase.NewApp(context.Background(), nil, opts)
	if err != nil {
		return nil, err
	}

	fcm, err := app.Messaging(context.Background())
	if err != nil {
		return nil, err
	}

	return &firebaseImpl{config: &fconfig, fcm: fcm}, nil
}

func getServiceAccountKey(sak string) ([]byte, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(sak)
	if err != nil {
		return nil, err
	}

	return decodedKey, nil
}
