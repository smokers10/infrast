package lib

import (
	"regexp"
)

func CredentialChecker(credentials string) (types string) {
	isEmail := isEmail(credentials)
	isPhoneNumber := isPhoneNumber(credentials)

	if isEmail {
		return "email"
	} else if isPhoneNumber {
		return "phone"
	}

	return "uncertain"
}

func isEmail(input string) bool {
	// Regular expression for validating email addresses
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	match, _ := regexp.MatchString(emailRegex, input)
	return match
}

func isPhoneNumber(input string) bool {
	// Regular expression for validating phone numbers
	phoneRegex := `^\+?(\d[\d-. ]+)?(\([\d-. ]+\))?[\d-. ]+\d$`

	match, _ := regexp.MatchString(phoneRegex, input)
	return match
}
