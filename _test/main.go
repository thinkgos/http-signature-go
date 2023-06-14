package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/things-go/httpsign/digest"
)

func main() {
	h := sha256.New()
	h.Write([]byte("1234"))
	fmt.Println(base64.StdEncoding.EncodeToString(h.Sum(nil)))

	d := digest.Sha{
		Name: "sha256",
		Hash: crypto.SHA256,
	}

	fmt.Println(d.Sign([]byte("1234")))

	fmt.Println(d.SignReader(bytes.NewReader([]byte("1234"))))
}
