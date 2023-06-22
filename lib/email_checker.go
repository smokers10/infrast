package lib

import "net/mail"

func EmailChecker(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
