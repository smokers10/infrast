package head

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHead(t *testing.T) {
	head, err := Head("config.yaml", "first-man-of-war")
	assert.NoError(t, err)
	assert.NotEmpty(t, head)
}
