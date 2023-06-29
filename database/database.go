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

// MongoDB implements contract.DatabaseContract
func (i *databaseImplementation) MongoDB() (*mongo.Database, error) {
	ctx, cancel := lib.InitializeContex()
	defer cancel()

	// set configuration
	option := options.Client().
		ApplyURI(i.Config.MongoDB.URI).
		SetMaxPoolSize(uint64(i.Config.MongoDB.MaxPool)).
		SetMinPoolSize(uint64(i.Config.MongoDB.MinPool)).
		SetMaxConnIdleTime(time.Duration(i.Config.MongoDB.MaxIdleConnections))

	// set up connection
	client, err := mongo.NewClient(option)
	if err != nil {
		return nil, err
	}

	// start connection
	client.Connect(ctx)
	db := client.Database(i.Config.MongoDB.DBName)

	// return database
	return db, nil
}

// PosgresSQL implements contract.DatabaseContract
func (i *databaseImplementation) PosgresSQL() (*sql.DB, error) {
	c := i.Config.PostgreSQL

	// Connection string
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", c.Host, c.Port, c.User, c.Password, c.DBName)

	// Open the database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	// Set connection pool settings
	db.SetMaxOpenConns(c.MaxOpenConnections)
	db.SetMaxIdleConns(c.MaxIdleConnections)
	db.SetConnMaxLifetime(time.Duration(c.ConnectionMaxLifeTime))

	return db, nil
}

func Database(Config *config.Configuration) contract.DatabaseContract {
	return &databaseImplementation{Config}
}
