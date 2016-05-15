package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	privKeyPath = "keys/app.rsa"     // openssl genrsa -out app.rsa keysize
	pubKeyPath  = "keys/app.rsa.pub" // openssl rsa -in app.rsa -pubout > app.rsa.pub
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func init() {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	fatal(err)

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	fatal(err)
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "No POST", r.Method)
		return
	}

	user := r.FormValue("user")
	pass := r.FormValue("pass")

	log.Printf("Auth: %s %s\n", user, pass)

	err, admin := getUser(user, pass)

	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Invalid username/password")
		return
	}

	t := jwt.New(jwt.GetSigningMethod("RS256"))

	if admin {
		t.Claims["AccessToken"] = "admin"
	} else {
		t.Claims["AccessToken"] = "user"
	}

	t.Claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
	tokenString, err := t.SignedString(signKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Token error!")
		log.Printf("Token error: %v\n", err)
		return
	}

	log.Printf("New token: %s\n", tokenString)

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "{\"token\":\"%s\"}", tokenString)

}

func getAccessLevel(r *http.Request) (error, int) {
	token, err := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) { return verifyKey, nil })

	level := -1
	if !token.Valid {
		return err, level
	}

	switch token.Claims["AccessToken"] {
	case "admin":
		level = 1
	case "user":
		level = 0
	default:
		level = -1
	}

	return err, level
}

func levelCheck(w http.ResponseWriter, r *http.Request, reqLevel int) bool {
	err, level := getAccessLevel(r)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
    fmt.Fprintf(w, "Token error!")
		log.Printf("Erro %v\n", err)
		return false
	}

	if level < reqLevel {
		w.WriteHeader(http.StatusUnauthorized)
    fmt.Fprintf(w, "Unauthorized!")
		log.Printf("Unauthorized\n")
		return false
	}

	return true
}

func adminAreaHandler(w http.ResponseWriter, r *http.Request) {
	if !levelCheck(w, r, 1) {
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "{\"isAdmin\":\"true\"}")
}

func userAreaHandler(w http.ResponseWriter, r *http.Request) {
	if !levelCheck(w, r, 0) {
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "{\"isAdmin\":\"false\"}")
}

func main() {
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/admin", adminAreaHandler)
	http.HandleFunc("/user", userAreaHandler)

	log.Println("Listening...")
	fatal(http.ListenAndServe(":8080", nil))
}
