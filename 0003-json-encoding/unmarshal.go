package main

import (
	"encoding/json"
	"fmt"
	"log"
)

type plant struct {
	Type string
}

func main() {
	p1 := plant{
		Type: "Calathea",
	}
	p2 := plant{
		Type: "Hera",
	}

	xp := []plant{p1, p2}

	bs, err := json.Marshal(xp)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("JSON", string(bs))

	//unmarshal below

	xp2 := []plant{}

	err = json.Unmarshal(bs, &xp2)
	if err != nil {
		log.Panic(err)
	}

	fmt.Println("GO", xp2)

}
