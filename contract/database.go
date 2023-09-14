package contract

import (
	"database/sql"

	"go.mongodb.org/mongo-driver/mongo"
)

type PGInstance struct {
	Label    string
	Instance *sql.DB
}

type MongoDBInstance struct {
	Label    string
	Instance *mongo.Database
}

type DatabaseContract interface {
	MongoDB() ([]MongoDBInstance, error)

	PostgresSQL() ([]PGInstance, error)

	GetPosgresInstance(instances []PGInstance, label string) (*PGInstance, error)

	GetMongoInstance(instances []MongoDBInstance, label string) (*MongoDBInstance, error)
}
