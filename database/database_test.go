package database

import (
	"context"
	"testing"
	"time"

	"github.com/smokers10/infrast/config"
	"github.com/stretchr/testify/assert"
)

func TestDatabase(t *testing.T) {
	// define mock config
	c := config.Configuration{
		PostgreSQL: []config.PostgresConfig{
			{
				Label:                 "General DB",
				Host:                  "localhost",
				Port:                  5432,
				User:                  "infrast",
				Password:              "infrastpass",
				DBName:                "infrastdb",
				MaxOpenConnections:    10,
				MaxIdleConnections:    2,
				ConnectionMaxLifeTime: 10,
			},
			{
				Label:                 "User Management",
				Host:                  "localhost",
				Port:                  5433,
				User:                  "infrastum",
				Password:              "infrastumpass",
				DBName:                "infrastdbum",
				MaxOpenConnections:    10,
				MaxIdleConnections:    2,
				ConnectionMaxLifeTime: 10,
			},
		},
		MongoDB: []config.MongoDBConfig{
			{
				Label:              "mongo-instance-1",
				URI:                "mongodb://infrast:infrastpass@localhost:27017/?authMechanism=SCRAM-SHA-1",
				MaxPool:            10,
				MinPool:            2,
				MaxIdleConnections: 5,
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	db := Database(&c)

	t.Run("PING POSTGRES INSTANCE", func(t *testing.T) {
		instances, err := db.PostgresSQL()
		if err != nil {
			t.Fatalf("error postgres connection : %v\n", err.Error())
		}

		for _, v := range instances {
			t.Run(v.Label, func(t *testing.T) {
				err := v.Instance.Ping()
				assert.NoError(t, err)
			})
		}
	})

	t.Run("PING MONGODB INSTANCE", func(t *testing.T) {
		instances, err := db.MongoDB()
		if err != nil {
			t.Fatalf("error mongo connection : %v\n", err.Error())
		}

		for _, v := range instances {
			t.Run(v.Label, func(t *testing.T) {
				if err := v.Instance.Client().Ping(ctx, nil); err != nil {
					t.Fatalf("error ping mongo connection on instance %s", v.Label)
				}
			})
		}
	})

	t.Run("Get PG Instance", func(t *testing.T) {
		instances, err := db.PostgresSQL()
		if err != nil {
			t.Fatalf("error postgres connection : %v\n", err.Error())
		}

		t.Run("not found", func(t *testing.T) {
			instance, err := db.GetPosgresInstance(instances, "ads")
			assert.Error(t, err)
			assert.Nil(t, instance)
		})

		t.Run("found", func(t *testing.T) {
			instance, err := db.GetPosgresInstance(instances, "General DB")
			assert.NoError(t, err)
			assert.NotNil(t, instance)
			err = instance.Instance.Ping()
			assert.NoError(t, err)
		})
	})

	t.Run("Get Mongo Instance", func(t *testing.T) {
		instances, err := db.MongoDB()
		if err != nil {
			t.Fatalf("error postgres connection : %v\n", err.Error())
		}

		t.Run("not found", func(t *testing.T) {
			instance, err := db.GetMongoInstance(instances, "ads")
			assert.Error(t, err)
			assert.Nil(t, instance)
		})

		t.Run("found", func(t *testing.T) {
			instance, err := db.GetMongoInstance(instances, "mongo-instance-1")
			assert.NoError(t, err)
			assert.NotNil(t, instance)
			instance.Instance.Client().Ping(ctx, nil)
		})
	})
}

func TestDatabaseErrorCon(t *testing.T) {
	// define mock config
	c := config.Configuration{
		PostgreSQL: []config.PostgresConfig{
			{
				Label:                 "General DB",
				Host:                  "dokalhost",
				Port:                  5432,
				User:                  "infrast",
				Password:              "sikonyo",
				DBName:                "infrastdb",
				MaxOpenConnections:    10,
				MaxIdleConnections:    2,
				ConnectionMaxLifeTime: 10,
			},
			{
				Label:                 "User Management",
				Host:                  "localhost",
				Port:                  5433,
				User:                  "infrastum",
				Password:              "infrastumpass",
				DBName:                "infrastdbum",
				MaxOpenConnections:    10,
				MaxIdleConnections:    2,
				ConnectionMaxLifeTime: 10,
			},
		},
		MongoDB: []config.MongoDBConfig{
			{
				Label:              "mongo-instance-1",
				URI:                "mongodb://infrast:sikonyo@dokalhost:27017/?authMechanism=SCRAM-SHA-1",
				MaxPool:            10,
				MinPool:            2,
				MaxIdleConnections: 5,
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	db := Database(&c)

	t.Run("PING ERROR POSTGRES INSTANCE", func(t *testing.T) {
		instances, err := db.PostgresSQL()
		if err != nil {
			t.Fatalf("error postgres connection : %v\n", err.Error())
		}

		for _, v := range instances {
			t.Run(v.Label, func(t *testing.T) {
				err := v.Instance.Ping()
				assert.Error(t, err)
			})
		}
	})

	t.Run("PING ERROR MONGODB INSTANCE", func(t *testing.T) {
		instances, err := db.MongoDB()
		if err != nil {
			t.Fatalf("error mongo connection : %v\n", err.Error())
		}

		for _, v := range instances {
			t.Run(v.Label, func(t *testing.T) {
				err := v.Instance.Client().Ping(ctx, nil)
				assert.Error(t, err)
			})
		}
	})
}
