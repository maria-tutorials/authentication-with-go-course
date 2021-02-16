package main

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

func createSession(e string, w http.ResponseWriter) error {
	sUUID := uuid.New().String()
	sessions[sUUID] = e
	token, err := createToken(sUUID)
	if err != nil {
		return fmt.Errorf("couldn't createtoken in createSession %w", err)
	}

	c := http.Cookie{
		Name:  "sessionID",
		Value: token,
		Path:  "/",
	}

	http.SetCookie(w, &c)
	return nil
}
