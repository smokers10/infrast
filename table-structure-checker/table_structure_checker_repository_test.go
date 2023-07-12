package tablestructurechecker

import (
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/smokers10/infrast/contract"
	"github.com/stretchr/testify/assert"
)

func TestStructureGetter(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := TableStructureCheckerRepository(db)
	tablename := "mytable"
	query := fmt.Sprintf(`SELECT column_name, data_type FROM INFORMATION_SCHEMA.COLUMNS where table_name = '%s'`, tablename)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		_, err := repository.StructureGetter("mytable")
		assert.Error(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on query", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WillReturnError(fmt.Errorf("error query"))

		_, err := repository.StructureGetter("mytable")
		assert.Error(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("successful execution", func(t *testing.T) {
		mock.ExpectPrepare(query)
		rows := sqlmock.NewRows([]string{"Field", "Type"}).
			AddRow("id", "int").
			AddRow("name", "varchar").
			AddRow("age", "int").
			AddRow("created_at", "datetime")
		mock.ExpectQuery(query).WillReturnRows(rows)

		columns, err := repository.StructureGetter("mytable")
		assert.NoError(t, err)

		expectedColumns := []contract.Column{
			{Field: "id", Type: "int"},
			{Field: "name", Type: "varchar"},
			{Field: "age", Type: "int"},
			{Field: "created_at", Type: "datetime"},
		}

		assert.Equal(t, expectedColumns, columns)
	})
}
