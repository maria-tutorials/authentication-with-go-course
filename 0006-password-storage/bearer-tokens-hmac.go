package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
)

var key = []byte{}

func main() {

	for i := 1; i <= 64; i++ {
		key = append(key, byte(i))
	}

}

func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha512.New, key)

	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error in 'signMessage' while hashing message: %w", err)
	}

	signature := h.Sum(nil)
	return signature, nil
}

func checkSignature(msg, sig []byte) (bool, error) {
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error in 'checkSignature' while getting message signature: %w", err)
	}

	same := hmac.Equal(newSig, sig)
	return same, nil
}
