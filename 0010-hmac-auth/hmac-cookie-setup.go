package main

import (
	"io"
	"net/http"
)

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/submit", submitHandler)
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

	//c :=
	_ = http.Cookie{
		Name:  "session",
		Value: "",
	}
}
