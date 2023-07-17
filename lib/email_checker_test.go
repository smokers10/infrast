package lib

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type table struct {
	ValueToCheck string
	Expected     bool
}

func TestMailChecker(t *testing.T) {
	testTable := []table{
		{
			ValueToCheck: "johndoe@gmail.com",
			Expected:     true,
		},
		{
			ValueToCheck: "johndoe@asu.com",
			Expected:     true,
		},
		{
			ValueToCheck: "08112123255@ausytda.net",
			Expected:     false,
		},
	}

	for _, v := range testTable {
		t.Run(fmt.Sprintf("Test %s", v.ValueToCheck), func(t *testing.T) {
			isEmail := EmailChecker(v.ValueToCheck)
			assert.Equal(t, v.Expected, isEmail)
		})
	}
}
