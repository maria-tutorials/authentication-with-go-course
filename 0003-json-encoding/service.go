package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type plant struct {
	Type string
}

func main() {
	http.HandleFunc("/encode", encodeHandler)
	http.HandleFunc("/decode", decodeHandler)
	http.ListenAndServe(":8080", nil)
}

func encodeHandler(w http.ResponseWriter, req *http.Request) {
	p1 := &plant{
		Type: "Codiaeum",
	}

	err := json.NewEncoder(w).Encode(p1)
	if err != nil {
		log.Println("Error encoding", err)
	}
}

func decodeHandler(w http.ResponseWriter, req *http.Request) {
	var p1 plant

	err := json.NewDecoder(req.Body).Decode(&p1)
	if err != nil {
		log.Println("Error decoding", err)
	}

	log.Println("Plant is: ", p1)
}
