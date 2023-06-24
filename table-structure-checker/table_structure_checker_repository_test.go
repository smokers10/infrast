package tablestructurechecker

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/smokers10/go-infrastructure/contract"
	"github.com/stretchr/testify/assert"
)

func TestStructureGetter(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := TableStructureCheckerRepository(db)
	query := "DESCRIBE"

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		_, err := repository.StructureGetter("nan")
		assert.Error(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on query", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WillReturnError(fmt.Errorf("error query"))

		_, err := repository.StructureGetter("nan")
		assert.Error(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("successful execution", func(t *testing.T) {
		mock.ExpectPrepare(query)
		rows := sqlmock.NewRows([]string{"Field", "Type", "Null", "Key", "Default", "Extra"}).
			AddRow("id", "int", "NO", "PRI", nil, "").
			AddRow("name", "varchar", "YES", "", sql.NullString{String: "John Doe", Valid: true}, "").
			AddRow("age", "int", "YES", "", nil, "").
			AddRow("created_at", "datetime", "NO", "", sql.NullString{String: "2021-01-01 12:00:00", Valid: true}, "DEFAULT_GENERATED")
		mock.ExpectQuery(query).WillReturnRows(rows)

		columns, err := repository.StructureGetter("mytable")
		assert.NoError(t, err)

		expectedColumns := []contract.Column{
			{Field: "id", Type: "int", Null: "NO", Key: "PRI", Default: sql.NullString{}, Extra: ""},
			{Field: "name", Type: "varchar", Null: "YES", Key: "", Default: sql.NullString{String: "John Doe", Valid: true}, Extra: ""},
			{Field: "age", Type: "int", Null: "YES", Key: "", Default: sql.NullString{}, Extra: ""},
			{Field: "created_at", Type: "datetime", Null: "NO", Key: "", Default: sql.NullString{String: "2021-01-01 12:00:00", Valid: true}, Extra: "DEFAULT_GENERATED"},
		}

		assert.Equal(t, expectedColumns, columns)
	})
}
