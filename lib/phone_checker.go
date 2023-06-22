package lib

import (
	"errors"

	"github.com/nyaruka/phonenumbers"
)

func PhoneChecker(phone string) (bool, error) {
	number, err := phonenumbers.Parse(phone, "")
	if err != nil {
		return false, err
	}

	if err != nil {
		return false, errors.New("parsing failed")
	}

	if !phonenumbers.IsValidNumber(number) {
		return false, nil
	}

	return true, nil
}
