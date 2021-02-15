package main

import (
	"io"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

var database = map[string][]byte{}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/register", registerHandler)
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
		<form action="/register" method="post">
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
