package main

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}

var key = []byte{}

func main() {
	for i := 1; i <= 64; i++ {
		key = append(key, byte(i))
	}
}

func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}

	if u.SessionID == 0 {
		return fmt.Errorf("Invalid session ID")
	}

	return nil
}

func createToken(c *UserClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, c)

	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("Error in 'CreateToken' when signing token: %v", err)
	}

	return signedToken, nil
}

func parseToken(token string) (*UserClaims, error) {
	t, err := jwt.ParseWithClaims(token, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("Invalid Signing Algorithm")
		}
		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("Error in 'parseToken' while parsing token: %w", err)
	}

	if !t.Valid {
		return nil, fmt.Errorf("Error in 'parseToken'. Invalid token")
	}

	return t.Claims.(*UserClaims), nil
}
