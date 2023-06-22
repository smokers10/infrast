package lib

import (
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
			ValueToCheck: "johndoe",
			Expected:     false,
		},
		{
			ValueToCheck: "08112123255",
			Expected:     false,
		},
	}

	for _, v := range testTable {
		isEmail := EmailChecker(v.ValueToCheck)
		t.Log(v.ValueToCheck)
		assert.Equal(t, v.Expected, isEmail)
	}
}
