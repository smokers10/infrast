package whatsapp

import (
	"errors"
	"fmt"
	"log"

	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"github.com/twilio/twilio-go"
	api "github.com/twilio/twilio-go/rest/api/v2010"
)

type whatsappImpl struct {
	config *config.Whatsapp
	client *twilio.RestClient
}

func (i *whatsappImpl) SendMessage(message string, to string) error {
	params := &api.CreateMessageParams{}
	params.SetFrom(fmt.Sprintf("whatsapp:%s", i.config.Sender))
	params.SetBody(message)
	params.SetTo(fmt.Sprintf("whatsapp:%s", to))

	resp, err := i.client.Api.CreateMessage(params)
	if err != nil {
		return err
	} else {
		log.Print(resp)
	}

	return nil
}

func Whatsapp(config *config.Configuration) (contract.Whatsapp, error) {
	wconfig := config.Whatsapp

	if wconfig.AuthToken == "" || wconfig.SID == "" {
		return nil, errors.New("error whatsapp : unauthorized access")
	}

	clientParams := twilio.ClientParams{
		Username:   "ghost ops",
		AccountSid: wconfig.SID,
		Password:   wconfig.AuthToken,
	}

	client := twilio.NewRestClientWithParams(clientParams)

	return &whatsappImpl{config: &wconfig, client: client}, nil
}
