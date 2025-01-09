package main

import (
	"encoding/hex"
	"fmt"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

func main() {
	var password string
	fmt.Print("Put your clear text password here: ")
	fmt.Scanln(&password)

	utf16Password := utf16.Encode([]rune(password))
	passwordBytes := make([]byte, len(utf16Password)*2)
	for i, char := range utf16Password {
		passwordBytes[i*2] = byte(char)
		passwordBytes[i*2+1] = byte(char >> 8)
	}
	hash := md4.New()
	hash.Write(passwordBytes)
	ntHash := hash.Sum(nil)

	fmt.Printf("NTLM hash: %v", hex.EncodeToString(ntHash))
}
