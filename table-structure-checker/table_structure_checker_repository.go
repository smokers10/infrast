package tablestructurechecker

import (
	"database/sql"
	"fmt"

	"github.com/smokers10/go-infrastructure/contract"
)

type tableStructureCheckerRepositoryImplementation struct{ db *sql.DB }

// StructureGetter implements contract.TableStructureCheckerRepository.
func (i *tableStructureCheckerRepositoryImplementation) StructureGetter(tablename string) (columns []contract.Column, failure error) {
	query := fmt.Sprintf(`SELECT column_name, data_type FROM INFORMATION_SCHEMA.COLUMNS where table_name = '%s'`, tablename)

	stmt, err := i.db.Prepare(query)
	if err != nil {
		return nil, err
	}

	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}

	defer stmt.Close()

	for rows.Next() {
		var column contract.Column
		err := rows.Scan(&column.Field, &column.Type)
		if err != nil {
			return nil, err
		}
		columns = append(columns, column)
	}

	return columns, nil
}

func TableStructureCheckerRepository(db *sql.DB) contract.TableStructureCheckerRepository {
	return &tableStructureCheckerRepositoryImplementation{db: db}
}
