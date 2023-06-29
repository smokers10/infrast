package mailer

import (
	"fmt"
	"net/smtp"

	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
)

type mailerImplementation struct {
	Config *config.Configuration
}

// Send implements contract.MailerContract
func (i *mailerImplementation) Send(reciever []string, subject string, template string) error {
	// set required data
	address := fmt.Sprintf("%s:%d", i.Config.SMTP.Host, i.Config.SMTP.Port)
	authentication := smtp.PlainAuth("", i.Config.SMTP.Username, i.Config.SMTP.Password, i.Config.SMTP.Host)

	// email construction
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	from := fmt.Sprintf("From: %s\n", i.Config.SMTP.Sender)
	mail_subject := fmt.Sprintf("Subject: %s \n", subject)
	message := []byte(from + mail_subject + mime + template)

	// send email process
	if err := smtp.SendMail(address, authentication, i.Config.SMTP.Username, reciever, message); err != nil {
		return err
	}

	return nil
}

func Mailer(Config *config.Configuration) contract.MailerContract {
	return &mailerImplementation{Config}
}
