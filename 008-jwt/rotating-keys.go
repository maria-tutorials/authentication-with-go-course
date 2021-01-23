package main

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
)

type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}

var key struct {
	key       []byte
	createdAt time.Time
}

var currentKID = ""
var keys = map[string]key{} // could be in a database

func main() {
	for i := 1; i <= 64; i++ {
		key = append(key, byte(i))
	}
}

// cron job to generate a new key for rotation
func generateNewKey() error {
	newKey := make([]byte, 64)
	_, err := rand.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("Error 'generateNewKey' while generating new key")
	}

	uuid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("Error 'generateNewKey' while generating uuid kid: %w", err)
	}

	keys[uid.String()] = key{
		key:       newKey,
		createdAt: time.Now(),
	}

	currentKID = uuid.String()

	return nil
}

// Valid validates the token claims
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

	signedToken, err := token.SignedString(keys[currentKID].key)
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

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("Invalid Key ID")
		}

		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("Invalid Key ID")
		}

		return k, nil
	})

	if err != nil {
		return nil, fmt.Errorf("Error in 'parseToken' while parsing token: %w", err)
	}

	if !t.Valid {
		return nil, fmt.Errorf("Error in 'parseToken'. Invalid token")
	}

	return t.Claims.(*UserClaims), nil
}
