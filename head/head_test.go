package head

import (
	"testing"

	"github.com/smokers10/go-infrastructure/lib"
	"github.com/stretchr/testify/assert"
)

func callHead() *head {
	h, err := Head("config")
	if err != nil {
		panic(err)
	}

	return h
}

func TestDatabase(t *testing.T) {
	h := callHead()
	db := h.DB

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

func TestEncryption(t *testing.T) {
	h := callHead()
	plaintext := "testhased"
	e := h.Encryption

	t.Run("TEST HASH", func(t *testing.T) {
		hashed := e.Hash(plaintext)

		assert.NotEmpty(t, hashed)
		t.Log(hashed)

		t.Run("TEST COMPARE", func(t *testing.T) {
			correct := e.Compare(plaintext, hashed)
			wrong := e.Compare("betrayal betray the betrayer", hashed)
			assert.True(t, correct)
			assert.False(t, wrong)
		})
	})
}

func TestIdentifier(t *testing.T) {
	h := callHead()
	identifier := h.Identfier
	id, err := identifier.MakeIdentifier()

	if err != nil {
		t.Fatalf("error make identifier : %v\n", err.Error())
	}

	t.Log(id)
	assert.NotEmpty(t, id)
}

func TestJsonWebToken(t *testing.T) {
	h := callHead()
	payload := map[string]interface{}{
		"name": "john doe",
		"age":  24,
	}
	jwt := h.JWT
	token, err := jwt.Sign(payload)

	t.Run("check sign token", func(t *testing.T) {
		assert.Empty(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("check parsing", func(t *testing.T) {
		p, err := jwt.ParseToken(token)

		assert.Empty(t, err)
		assert.NotEmpty(t, p["name"].(string))
		assert.NotEmpty(t, p["age"].(float64))
		assert.Equal(t, "john doe", p["name"].(string))
		assert.Equal(t, 24, int(p["age"].(float64)))
	})
}

func TestMailer(t *testing.T) {
	h := callHead()

	smtp := h.Mailer

	err := smtp.Send([]string{"lpiexecutive@gmail.com"}, "good morning!", "hey good morning budy!")
	assert.Empty(t, err)
}
