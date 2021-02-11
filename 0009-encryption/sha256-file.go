package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	f, err := os.Open("sample-file.txt")
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	h := sha256.New()

	_, err = io.Copy(h, f)
	if err != nil {
		log.Fatalln("couldn't io.copy", err)
	}

	xb := h.Sum(nil)
	fmt.Printf("%x\n", xb)
}
