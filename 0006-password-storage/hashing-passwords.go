package main

import (
	"fmt"
	"log"

	bcrypt "golang.org/x/crypto/bcrypt"
)

func main() {
	password := "123456789"

	hashedPassword, err := hashPassword(password)
	if err != nil {
		panic(err)
	}

	err = comparePassword(password, hashedPassword)
	if err != nil {
		log.Fatal("Can't log in")
	}

	log.Println("*Hacker voice*: I'm in")

}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error when generating bcypt hash: %w", err)
	}
	return bs, nil
}

func comparePassword(password string, hashedPassword []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		return fmt.Errorf("Passwords do not match")
	}
	return nil
}
