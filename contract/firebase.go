package contract

import (
	"firebase.google.com/go/messaging"
	"github.com/stretchr/testify/mock"
)

type Firebase interface {
	SendMessage(data *messaging.Message) error

	SendMulticastMessage(data *messaging.MulticastMessage) error
}

type FirebaseMock struct {
	Mock mock.Mock
}

func (m *FirebaseMock) SendMessage(data *messaging.Message) error {
	args := m.Mock.Called(data)
	return args.Error(0)
}

func (m *FirebaseMock) SendMulticastMessage(data *messaging.MulticastMessage) error {
	args := m.Mock.Called(data)
	return args.Error(0)
}

/*
example code

func SendPushNotification(deviceTokens []string) error {
   decodedKey, err := getDecodedFireBaseKey()

   if err != nil {
      return err
   }

  opts :=  []option.ClientOption{option.WithCredentialsJSON(decodedKey)}

  app, err := firebase.NewApp(context.Background(), nil, opts...)

  if err != nil {
     log.Debug("Error in initializing firebase : %s", err)
     return err
  }

  fcmClient, err := app.Messaging(context.Background())

  if err != nil {
     return err
  }

  response, err := fcmClient.SendMulticast(context.Background(), &messaging.MulticastMessage{
   Notification: &messaging.Notification{
     Title: "Congratulations!!",
     Body:  "You have just implement push notification",
   },
   Tokens: deviceTokens,
  })

  if err != nil {
     return err
  }

  log.Debug("Response success count : ", response.SuccessCount)
  log.Debug("Response failure count : ", response.FailureCount)

  return nil
}
*/
