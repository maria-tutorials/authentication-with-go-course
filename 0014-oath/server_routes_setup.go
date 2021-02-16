package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var STATE = "0000"

var githubOauthConfig = &oauth2.Config{
	ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
	Endpoint:     github.Endpoint,
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/oauth/github", startGithubOauthHandler)
	http.HandleFunc("/oauth2/receive", finishGithubOauthHandler) //define url in github app
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

func startGithubOauthHandler(w http.ResponseWriter, req *http.Request) {
	redirectURL := githubOauthConfig.AuthCodeURL(STATE) //state should be in a database with attempts
	http.Redirect(w, req, redirectURL, http.StatusSeeOther)
}

func finishGithubOauthHandler(w http.ResponseWriter, req *http.Request) {
	code := req.FormValue("code")
	state := req.FormValue("state")

	ctx := req.Context()

	if state != STATE {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	token, err := githubOauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	ts := githubOauthConfig.TokenSource(ctx, token)
	client := oauth2.NewClient(ctx, ts) //authenticated with github

	body := strings.NewReader(`{"query": "query {viewer {id}}"}`)
	resp, err := client.Post("https://api.github.com/graphql", "application/json", body)
	if err != nil {
		http.Error(w, "Failed to get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	log.Println(string(bs))
}
