package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
)

type user struct {
	password    []byte
	displayName string
}

var oauth = &oauth2.Config{
	ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
	Endpoint:     amazon.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth/amazon/receive",
	Scopes:       []string{"profile"},
}

// key is email, value is user
var database = map[string]user{}

// key is sessionid, value is email
var sessions = map[string]string{}

// key is uuid from oauth login, value is expiration time
var oauthExp = map[string]time.Time{}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	http.HandleFunc("/oauth/amazon/login", startAmazonOauthHandler)
	http.HandleFunc("/oauth/amazon/receive", receiveAmazonOauthHandler)

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

		<h3> login with amazon </h3>
		<form action="/oauth/amazon/login" method="post">
			<input type="submit" value="AMAZON LOGIN">
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
		<form action="/logout" method="post">
			<input type="submit" value="logout" />
		</form>
		</body>
		</html>`
	}

	io.WriteString(w, html)
}

func registerHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Redirect(w, req, "/", http.StatusMethodNotAllowed)
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
		http.Redirect(w, req, "/", http.StatusMethodNotAllowed)
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

func logoutHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Redirect(w, req, "/", http.StatusMethodNotAllowed)
		return
	}

	c, err := req.Cookie("session")
	if err != nil {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	sid, err := parseToken(c.Value)
	if err != nil {
		fmt.Println(err)
	}

	delete(sessions, sid)

	c.MaxAge = -1 //expire
	http.SetCookie(w, c)

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func startAmazonOauthHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Redirect(w, req, "/", http.StatusMethodNotAllowed) //METHOD NOT ALLOWED?
		return
	}

	id := uuid.New().String()
	oauthExp[id] = time.Now().Add(time.Hour)

	// here we redirect to amazon at the AuthURL endpoint
	http.Redirect(w, req, oauth.AuthCodeURL(id), http.StatusSeeOther)
}

func receiveAmazonOauthHandler(w http.ResponseWriter, req *http.Request) {
	state := req.FormValue("state")
	code := req.FormValue("code")
	if state == "" || code == "" {
		http.Error(w, "Failed to authorize at amazon", http.StatusUnauthorized)
		return
	}

	expT := oauthExp[state]
	if time.Now().After(expT) {
		http.Error(w, "Amazon took too long to authorize", http.StatusRequestTimeout)
		return
	}

	ctx := req.Context()

	token, err := oauth.Exchange(ctx, code)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	ts := oauth.TokenSource(ctx, token)
	c := oauth2.NewClient(ctx, ts)

	resp, err := c.Get("https://api.amazon.com/user/profile")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil && (resp.StatusCode < 200 || resp.StatusCode > 299) {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	io.WriteString(w, string(bs))
}
