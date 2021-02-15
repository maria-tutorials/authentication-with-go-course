package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var key = []byte("my croton has a bunch of new leaves :)")

type customClaimsJWT struct {
	jwt.StandardClaims
	SID string
}

type user struct {
	password    []byte
	displayName string
}

var database = map[string]user{}
var sessions = map[string]string{}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.ListenAndServe(":8080", nil)
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	c, err := req.Cookie("session")
	if err != nil {
		c = &http.Cookie{
			Name:  "session",
			Value: "",
		}
	}

	sid, err := parseToken(c.Value)
	if err != nil {
		fmt.Println(err)
	}

	name := ""
	if sid != "" {
		email := sessions[sid]
		name = database[email].displayName
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
		<h3> register </h3>
		<form action="/register" method="post">
			<input type="text" name="name" placeholder="Display Name" />
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

	if name != "" {
		html = `
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<meta http-equiv="X-UA-Compatible" content="ie=edge">
			<title>HMAC Example (Part 1)</title>
		</head>
		<body>
		<h3> Welcome back ` + name + `</h3>
		</body>
		</html>`
	}

	io.WriteString(w, html)
}

func registerHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	email := req.FormValue("email")
	name := req.FormValue("name")
	password := req.FormValue("password")
	if email == "" || password == "" || name == "" {
		http.Redirect(w, req, "/", http.StatusBadRequest)
		return
	}

	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		http.Error(w, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	database[email] = user{
		displayName: name,
		password:    b,
	}

	http.Redirect(w, req, "/", http.StatusSeeOther)
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

	user, ok := database[email]
	if !ok {
		http.Error(w, "Username and/or password do not match", http.StatusForbidden)
		return
	}

	err := bcrypt.CompareHashAndPassword(user.password, []byte(password))
	if err != nil {
		http.Error(w, "Username and/or password do not match", http.StatusForbidden)
		return
	}

	sUUID := uuid.New().String()
	sessions[sUUID] = email
	token, err := createToken(sUUID)
	if err != nil {
		//should log error
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	c := http.Cookie{
		Name:  "session",
		Value: token,
	}
	http.SetCookie(w, &c)

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

// createToken receives session id and returns an hmac signed jwt or error
func createToken(sid string) (string, error) {
	cc := customClaimsJWT{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 5).Unix(),
		},
		SID: sid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cc)
	st, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return st, nil
}

// parseToken receives the signed jwt and returns session id
func parseToken(token string) (string, error) {
	pt, err := jwt.ParseWithClaims(token, &customClaimsJWT{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("invalid signing method algorithm")
		}
		return key, nil
	})
	if err != nil {
		return "", err
	}

	if !pt.Valid {
		return "", errors.New("INVALID TOKEN M8")
	}

	return pt.Claims.(*customClaimsJWT).SID, nil
}
