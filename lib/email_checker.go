package lib

import (
	"log"
	"net"
	"net/mail"
	"strings"
)

func EmailChecker(email string) bool {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	domain := extractDomain(email)
	_, err = net.LookupMX(domain)
	if err != nil {
		log.Println(err.Error())
		return false
	}

	return true
}

func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}
