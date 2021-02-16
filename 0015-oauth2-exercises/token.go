package main

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var key = []byte("my croton has a bunch of new leaves :)")

type customClaimsJWT struct {
	jwt.StandardClaims
	SID string
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
