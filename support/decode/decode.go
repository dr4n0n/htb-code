package main

import (
	"encoding/base64"
	"fmt"
)

func main() {
	encryptedPassword := "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
	key := "armando"

	array, err := base64.StdEncoding.DecodeString(encryptedPassword)
	if err != nil {
		fmt.Printf("Error decoding base64 string: %v\n", err)
		return
	}

	var decryptedPassword string
	for i := 0; i < len(array); i++ {
		decryptedPassword += string(array[i] ^ key[i%len(key)] ^ 223)
	}

	fmt.Printf("Decrypted password found: %s\n", decryptedPassword)
}
