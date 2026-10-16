package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	encoded, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(dst, encoded)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%#v\n", dst[:n])
}
