package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func cleanUp (db *sql.DB) {
	db.Exec(`DROP TABLE IF EXISTS keys`)
	db.Close()
}



func TestAuth(t *testing.T) {

	db, _ = sql.Open("sqlite3", "test.db")
	//Create the schema
	db.Exec(
		`CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	
	t.Run("auth not POST", func(t *testing.T) {

		request, _ := http.NewRequest(http.MethodGet, "localhost:8080/auth", nil)
		response := httptest.NewRecorder()

		handleAuth(response, request)

		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected %q", http.StatusMethodNotAllowed)
		}
	})

	t.Run("auth no expired", func(t *testing.T) {

		request, _ := http.NewRequest(http.MethodPost, "localhost:8080/auth", nil)
		response := httptest.NewRecorder()

		handleAuth(response, request)

		got := response.Body.String()

		JWTParts := strings.Split(got, ".")

		decoded, _ := base64.RawStdEncoding.DecodeString(JWTParts[1])
		var payload Payload
		err := json.Unmarshal(decoded, &payload)
		if err != nil {
			log.Fatal("Error reading Payload")
		}
		if payload.Exp <= int(time.Now().Unix()) {
			t.Errorf("JWT is expired")
		}

	})


	
	t.Run("auth expired" ,func(t *testing.T) {

		request, _ := http.NewRequest(http.MethodPost, "localhost:8080/auth?expired", nil)
		response := httptest.NewRecorder()

		handleAuth(response, request)

		got := response.Body.String()

		JWTParts := strings.Split(got, ".")

		decoded, _ := base64.RawStdEncoding.DecodeString(JWTParts[1])
		var payload Payload
		err := json.Unmarshal(decoded, &payload)
		if err != nil {
			log.Fatal("Error reading Payload")
		}

		if !(payload.Exp <= int(time.Now().Unix())) {
			t.Errorf("JWT is not expired")
		}
	})

	// cleanUp(db)

}


func TestJWKS(t *testing.T) {
	db, _ = sql.Open("sqlite3", "test.db")
	
	
	//Create the schema
	db.Exec(
		`CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)

	

	t.Run("auth not Get", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodPost, "localhost:8080/.well-known/jwks.json", nil)
		response := httptest.NewRecorder()

		handleJWKS(response, request)

		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected %q", http.StatusMethodNotAllowed)
		}		
	})

	t.Run("Get JWKS", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "localhost:8080/.well-known/jwks.json", nil)
		response := httptest.NewRecorder()

		handleJWKS(response, request)
		
		// got := response.Body.String()
		if response.Body.String() == "" {
			t.Errorf("No JWKS returned")
		}


	})


}

func TestKeyPairs(t *testing.T) {
	_, _, e := generateKeyPairs(0)
	if e == nil {
		t.Errorf("No error returned from key pairs")
	}
	
}

