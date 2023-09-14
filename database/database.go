package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"github.com/smokers10/infrast/lib"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type databaseImplementation struct {
	Config *config.Configuration
}

// GetMongoInstance implements contract.DatabaseContract.
func (*databaseImplementation) GetMongoInstance(instances []contract.MongoDBInstance, label string) (*contract.MongoDBInstance, error) {
	for i := 0; i < len(instances); i++ {
		instance := instances[i]
		if instance.Label == label {
			return &instance, nil
		}
	}

	return nil, fmt.Errorf("mongo db instance labeled %s not found", label)
}

// GetPosgresInstance implements contract.DatabaseContract.
func (*databaseImplementation) GetPosgresInstance(instances []contract.PGInstance, label string) (*contract.PGInstance, error) {
	for i := 0; i < len(instances); i++ {
		instance := instances[i]
		if instance.Label == label {
			return &instance, nil
		}
	}

	return nil, fmt.Errorf("postgres instance labeled %s not found", label)
}

// MongoDB implements contract.DatabaseContract
func (i *databaseImplementation) MongoDB() ([]contract.MongoDBInstance, error) {
	c := i.Config.MongoDB
	instances := []contract.MongoDBInstance{}

	for i := 0; i < len(c); i++ {
		ctx, cancel := lib.InitializeContex()
		defer cancel()

		// set configuration
		option := options.Client().
			ApplyURI(c[i].URI).
			SetMaxPoolSize(uint64(c[i].MaxPool)).
			SetMinPoolSize(uint64(c[i].MinPool)).
			SetMaxConnIdleTime(time.Duration(c[i].MaxIdleConnections))

		// set up connection
		client, err := mongo.Connect(ctx, option)
		if err != nil {
			return nil, err
		}

		// start connection
		db := client.Database(c[i].DBName)

		// append db instance
		instance := contract.MongoDBInstance{
			Label:    c[i].Label,
			Instance: db,
		}

		instances = append(instances, instance)
	}

	return instances, nil
}

// PostgresSQL implements contract.DatabaseContract
func (i *databaseImplementation) PostgresSQL() ([]contract.PGInstance, error) {
	c := i.Config.PostgreSQL
	instances := []contract.PGInstance{}

	for i := 0; i < len(c); i++ {
		// Connection string
		connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", c[i].Host, c[i].Port, c[i].User, c[i].Password, c[i].DBName)

		// Open the database connection
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			return nil, err
		}

		// Set connection pool settings
		db.SetMaxOpenConns(c[i].MaxOpenConnections)
		db.SetMaxIdleConns(c[i].MaxIdleConnections)
		db.SetConnMaxLifetime(time.Duration(c[i].ConnectionMaxLifeTime))

		// appending instances
		instance := contract.PGInstance{
			Label:    c[i].Label,
			Instance: db,
		}
		instances = append(instances, instance)
	}

	return instances, nil
}

func Database(Config *config.Configuration) contract.DatabaseContract {
	return &databaseImplementation{Config: Config}
}
