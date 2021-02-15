package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var database = map[string][]byte{}
var key = []byte("my croton has a bunch of new leaves :)")

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.ListenAndServe(":8080", nil)
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	html := `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>HMAC Example (Part 1)</title>
	</head>
	<body>
		<h3> register </h3>
		<form action="/register" method="post">
			<input type="email" name="email" />
			<input type="password" name="password" />
			<input type="submit" />
		</form>
		<h3> login </h3>
		<form action="/login" method="post">
			<input type="email" name="email" />
			<input type="password" name="password" />
			<input type="submit" />
		</form>
	</body>
	</html>`

	io.WriteString(w, html)
}

func registerHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	email := req.FormValue("email")
	password := req.FormValue("password")
	if email == "" || password == "" {
		http.Redirect(w, req, "/", http.StatusBadRequest)
		return
	}

	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		http.Error(w, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	database[email] = b

	w.WriteHeader(http.StatusOK)
}

func loginHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	email := req.FormValue("email")
	password := req.FormValue("password")
	if email == "" || password == "" {
		http.Redirect(w, req, "/", http.StatusBadRequest)
		return
	}

	hashedPass, ok := database[email]
	if !ok {
		http.Error(w, "Username and/or password do not match", http.StatusForbidden)
		return
	}

	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	if err != nil {
		http.Error(w, "Username and/or password do not match", http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// createToken receives session id and returns an hmac signed token encoded in b64
func createToken(sid string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sid))
	//signedMac := fmt.Sprintf("%x", mac.Sum(nil)) //hex
	signedMac := base64.StdEncoding.EncodeToString(mac.Sum(nil)) //base64

	return signedMac + "|" + sid
}

// parseToken gets signed string and returns session id
func parseToken(signed string) (string, error) {
	xs := strings.SplitN(signed, "|", 2)
	if len(xs) != 2 {
		return "", fmt.Errorf("NOT VALID")
	}

	b64 := xs[0]
	decodedToken, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(xs[1]))

	if !hmac.Equal(decodedToken, mac.Sum(nil)) {
		return "", fmt.Errorf("NOT VALID")
	}

	return xs[1], nil
}
