package tablestructurechecker

import (
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	"github.com/smokers10/go-infrastructure/contract"
)

type tableStructureCheckerRepositoryImplementation struct{ db *sql.DB }

// StructureGetter implements contract.TableStructureCheckerRepository.
func (i *tableStructureCheckerRepositoryImplementation) StructureGetter(tablename string) (columns []contract.Column, failure error) {
	query := fmt.Sprintf("DESCRIBE %s", pq.QuoteIdentifier(tablename))

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
		err := rows.Scan(&column.Field, &column.Type, &column.Null, &column.Key, &column.Default, &column.Extra)
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
