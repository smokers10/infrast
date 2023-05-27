package contract

import (
	"database/sql"

	"go.mongodb.org/mongo-driver/mongo"
)

type DatabaseContract interface {
	MongoDB() (*mongo.Database, error)

	PosgresSQL() (*sql.DB, error)
}
