package database

import (
	"testing"

	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/lib"
)

func TestDatabase(t *testing.T) {
	// define mock config
	c := config.Configuration{
		PostgreSQL: config.PostgresConfig{
			Host:                  "localhost",
			Port:                  5432,
			User:                  "testuser",
			Password:              "testpass",
			DBName:                "testdb",
			MaxOpenConnections:    10,
			MaxIdleConnections:    2,
			ConnectionMaxLifeTime: 10,
		},
		MongoDB: config.MongoDBConfig{
			URI:                "mongodb://testuser:testpass@localhost:27017/?authMechanism=SCRAM-SHA-1",
			MaxPool:            10,
			MinPool:            2,
			MaxIdleConnections: 1,
			DBName:             "testing",
		},
	}

	db := Database(&c)

	// ping mongo
	t.Run("PING MONGO", func(t *testing.T) {
		mongo, err := db.MongoDB()
		if err != nil {
			t.Fatalf("error mongo connection : %v\n", err.Error())
		}
		ctx, cncl := lib.InitializeContex()
		defer cncl()

		if err := mongo.Client().Ping(ctx, nil); err != nil {
			t.Fatalf("error ping : %v\n", err.Error())
		}
	})

	t.Run("PING POSTGRE", func(t *testing.T) {
		pq, err := db.PosgresSQL()
		if err != nil {
			t.Fatalf("error mongo connection : %v\n", err.Error())
		}

		if err := pq.Ping(); err != nil {
			t.Fatalf("error ping : %v\n", err.Error())
		}
	})
}
