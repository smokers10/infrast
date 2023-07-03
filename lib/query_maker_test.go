package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserQueryMaker(t *testing.T) {
	credentials := []string{"username", "email"}

	sc, wc := UserQueryMaker(credentials)
	t.Logf("select clause : %s", sc)
	t.Logf("where clause : %s", wc)

	assert.Equal(t, "username, email", sc)
	assert.Equal(t, "username = $1 OR email = $1", wc)
}

func TestInsertQueryValueMaker(t *testing.T) {
	values := []string{"username01", "+628112123255", "1"}

	value := InsertQueryValueMaker(values...)
	t.Logf("value clause : %v", value)
	assert.Equal(t, "('username01', '+628112123255', 1)", value)
}

func TestWhereClause(t *testing.T) {
	credentials := []string{"username", "email"}

	wc := WhereClause(credentials, "$2")
	t.Logf("where clause : %s", wc)
	assert.Equal(t, "username = $2 OR email = $2", wc)
}
