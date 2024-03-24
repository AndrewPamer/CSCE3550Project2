package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type JWK struct {
	Kid string	`json:"kid"`
	Alg string	`json:"alg"`
	Kty string	`json:"kty"`
	Use string	`json:"use"`
	N string	`json:"n"`
	E string	`json:"e"`
	Exp int		`json:"exp"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type Header struct {
	Alg string	`json:"alg"`
	Typ string	`json:"typ"`
	Kid string	`json:"kid"`
}

type Payload struct {
	Data string	`json:"data"`
	Exp int		`json:"exp"`
}
	var db *sql.DB



func main()  {

	//Open the db
	// var err error
	db, _ = sql.Open("sqlite3", "totally_not_my_privateKeys.db")

	defer db.Close()

	//Create the schema
	db.Exec(
		`CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)


	//Set up the server multiplexer
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", handleAuth)
	mux.HandleFunc("/.well-known/jwks.json", handleJWKS)

	//Listen for incoming requests on port 8080
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))
}



func generateKeyPairs(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, e := rsa.GenerateKey(rand.Reader, bits)
	if e != nil {
		return nil, nil, e
	}
	
	//Validate the private key
	e = privateKey.Validate()
	if e != nil {
		return nil, nil, e
	}

	publicKey := &privateKey.PublicKey

	return privateKey, publicKey, e
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST is allowed", http.StatusMethodNotAllowed)
		return
	}
	bits := 2048
	//Check for the expired query parameter
	hasExpired := r.URL.Query().Has("expired")

	//First, check if there is a unexpired and expired key in the database
	var unexpKeys int
	// fmt.Println(db)
	if db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp > ?", time.Now().Unix()).Scan(&unexpKeys) != nil{
		log.Fatal("Error reading db")
	}


	//Add an unexpired key if there isn't any
	if unexpKeys == 0 {
		privateKey, _, e := generateKeyPairs(bits)
		if e != nil {
			log.Fatal("Error generating private key")
		}
		//Create the PEM
		privateKeyPem := &pem.Block {
			Type: "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		var privateKeyRow bytes.Buffer

		pem.Encode(&privateKeyRow, privateKeyPem)
		_, err := db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", privateKeyRow.String(), time.Now().Unix() + 86400)
		if err != nil {
			log.Fatal("Error adding unexpired private key to the database")
		}
	}



	var expKeys int
	if db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp < ?", time.Now().Unix()).Scan(&expKeys) != nil{
		log.Fatal("Error reading db")
	}



	//Add an expired key if there isn't one
	if expKeys == 0 {
		privateKey, _, e := generateKeyPairs(bits)
		if e != nil {
			log.Fatal("Error generating private key")
		}
		//Create the PEM
		privateKeyPem := &pem.Block {
			Type: "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		var privateKeyRow bytes.Buffer

		pem.Encode(&privateKeyRow, privateKeyPem)
		_, err := db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", privateKeyRow.String(), time.Now().Unix() - 1)
		if err != nil {
			log.Fatal("Error adding expired private key to the database")
		}
	}

	


	//1. Get a private key from the database
	var query string
	if hasExpired {
		query = fmt.Sprintf("SELECT kid, key, exp FROM keys WHERE exp < %d", time.Now().Unix())
	} else {
		query = "SELECT kid, key, exp FROM keys"
	}

	var kid int
	var privateKeyFromDB []byte
	var expTime int
	err := db.QueryRow(query).Scan(&kid, &privateKeyFromDB, &expTime)
	if err != nil{
		log.Fatal("Error reading a private key from the database")
	}
	pemBlock, _ := pem.Decode(privateKeyFromDB)
	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		log.Fatal("Error converting pem from database to private key")
	}

	//2. Create a JWT and sign it with the private key
	JWT := createJWT(fmt.Sprint(kid), expTime, privateKey)

	//3. Write it back to the user
	w.Write([]byte(JWT))
}

func createJWT(kid string, expiredTime int, privateKey *rsa.PrivateKey ) (string) {

	//Create a header and payload
	header := Header{Alg:"RS256", Typ: "JWT", Kid: kid}
	payload := Payload{Data:"Example data", Exp: expiredTime}

	//Convert the header and payload to a JSON format
 
	headJSON, e := json.Marshal(header)
	if e != nil {
		log.Fatal("Error converting JWT Header to JSON")
	}
	payloadJSON, e := json.Marshal(payload)
	if e != nil {
		log.Fatal("Error converting JWT Payload to JSON")
	}

	//Encode the header and payload into base64
	encodedHeader := strings.TrimRight(base64.URLEncoding.EncodeToString(headJSON), "=")
	encodedPayload := strings.TrimRight(base64.URLEncoding.EncodeToString(payloadJSON), "=")

	signatureMessage := encodedHeader + "." + encodedPayload
	h := sha256.New()
	h.Write([]byte(signatureMessage))
	d := h.Sum(nil)

	//Create the signature
	signature, _ := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, d)
	// if e != nil {
	// 	log.Fatal("Error creating JWT signature")
	// }

	//Create the actual JWT
	encodedSignature := strings.TrimRight(base64.URLEncoding.EncodeToString(signature), "=")
	return encodedHeader + "." + encodedPayload + "." + encodedSignature
}

// func createJWK(publicKey *rsa.PublicKey, isExpired bool) (JWK) {
// 	kid := uuid.New()
	
// 	encodedN := strings.TrimRight(base64.URLEncoding.EncodeToString(publicKey.N.Bytes()), "=")
	
// 	eVal := big.NewInt(int64(publicKey.E))
	
// 	encodedE := strings.TrimRight(base64.URLEncoding.EncodeToString(eVal.Bytes()), "=")

// 	expireTime := int(time.Now().Unix())

// 	//Add a day
// 	if !isExpired {
// 		expireTime += 86400
// 	}
	
// 	//Generate a JWK entry
// 	newJWK := JWK{Kid: kid.String(), Alg: "RS256", Kty: "RSA", Use: "sig", N: encodedN, E: encodedE, Exp: expireTime} 
// 	return newJWK
// }

func createPrivateJWK(kid string, publicKey *rsa.PrivateKey, expiredTime int) (JWK) {
	
	encodedN := strings.TrimRight(base64.URLEncoding.EncodeToString(publicKey.N.Bytes()), "=")
	
	eVal := big.NewInt(int64(publicKey.E))
	
	encodedE := strings.TrimRight(base64.URLEncoding.EncodeToString(eVal.Bytes()), "=")

	// expireTime := int(time.Now().Unix())

	//Add a day
	// if !isExpired {
	// 	expireTime += 86400
	// }
	
	//Generate a JWK entry
	newJWK := JWK{Kid: kid, Alg: "RS256", Kty: "RSA", Use: "sig", N: encodedN, E: encodedE, Exp: expiredTime} 
	return newJWK
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET is allowed", http.StatusMethodNotAllowed)
		return
	}

	var jwks JWKS
	var (
		kid int
		privKeyPem []byte
		expTime int
	)
	
	//1. Get all the unexpired keys from the database
	keys, err := db.Query("SELECT * FROM keys WHERE exp > ?", time.Now().Unix())
	if err != nil {
		log.Fatal("Error reading unexpired keys from the database")
	}

	if keys.Next() {
		if keys.Scan(&kid, &privKeyPem, &expTime) != nil {
			log.Fatal(err)
		}
		pemBlock, _ := pem.Decode(privKeyPem)
		privateKey, _ := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Error converting pem from database to private key")
		}

		//2. Create a JWK
		jwk := createPrivateJWK(fmt.Sprint(kid), privateKey, expTime)
		jwks.Keys = append(jwks.Keys, jwk)
	}

	returnJWKS, _ := json.Marshal(jwks)

	w.Write(returnJWKS)
}







