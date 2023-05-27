package identifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIdentifier(t *testing.T) {
	id, err := Identifier().MakeIdentifier()

	if err != nil {
		t.Fatalf("error make identifier : %v\n", err.Error())
	}

	t.Log(id)
	assert.NotEmpty(t, id)
}
