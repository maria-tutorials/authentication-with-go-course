package main

import (
	"fmt"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var githubOauthConfig = &oauth2.Config{
	ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
	Endpoint:     github.Endpoint,
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/oauth/github", githubOauthHandler)
	http.ListenAndServe(":8080", nil)
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Fprint(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<title>Oauth2 in action</title>
	</head>
	<body>
		<form action="/oauth/github" method="post">
			<input type="submit" value="Login with Github">
		</form>
	</body>
	</html>`)
}

func githubOauthHandler(w http.ResponseWriter, req *http.Request) {
	redirectURL := githubOauthConfig.AuthCodeURL("0000") //state should be in a database with attempts
	http.Redirect(w, req, redirectURL, http.StatusSeeOther)
}
