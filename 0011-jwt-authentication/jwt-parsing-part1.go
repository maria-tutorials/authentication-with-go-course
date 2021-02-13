package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type claims struct {
	jwt.StandardClaims
	Email string
}

const key = "sakura miyawaki"

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/submit", submitHandler)
	http.ListenAndServe(":8080", nil)
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	c, err := req.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}

	ss := c.Value

	token, err := jwt.ParseWithClaims(ss, &claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("Invalid Signing Algorithm")
		}

		return []byte(key), nil
	})

	/**
	 StandardClaims has the
		Valid() method,
		meaning it implements the Claims interface

	  So ParseWithClaims will call Valid()
	    and set the field Valid
	**/

	valid := err == nil && token.Valid
	message := "Not logged"
	if valid {
		message := "Logged in"

		tokenClaims := token.Claims.(*claims)
		fmt.Println(tokenClaims.Email)
		fmt.Println(tokenClaims.ExpiresAt)
	}

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
		<p> Cookie value is:` + c.Value + `</p>
		<p>` + message + `</p>
		<form action="/submit" method="post">
			<input type="email" name="email" />
			<input type="submit" />
		</form>
	</body>
	</html>`
	io.WriteString(w, html)
}

func submitHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	email := req.FormValue("email")
	if email == "" {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	ss, err := getJWT(email)
	if err != nil {
		http.Error(w, "failed to get JWT", http.StatusInternalServerError)
	}

	c := http.Cookie{
		Name:  "session",
		Value: ss,
	}

	http.SetCookie(w, &c)

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func getJWT(msg string) (string, error) {
	c := claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 5).Unix(),
		},
		Email: msg,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &c)

	ss, err := token.SignedString([]byte(key))
	if err != nil {
		return "", fmt.Errorf("Error %w, on getJWT", err)
	}

	return ss, nil
}
