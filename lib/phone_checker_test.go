package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPhoneChecker(t *testing.T) {
	table := []table{
		{ValueToCheck: "+628112123255", Expected: true},
		{ValueToCheck: "+6281abcd123!!!3", Expected: false},
	}

	for _, v := range table {
		actual, err := PhoneChecker(v.ValueToCheck)
		if err != nil {
			t.Logf("error phone checker : %v\n", err.Error())
		}

		assert.Equal(t, v.Expected, actual)
	}
}
