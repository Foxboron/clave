package clave

import (
	"bytes"
	"io"
	"log"
	"os/exec"
)

func GetPublicKey(keyID string) io.Reader {
	out, err := exec.Command("/usr/bin/gpg", "--export", "--armor", keyID).Output()
	// out, err := exec.Command("cat", "./tests/test.pubkey").Output()
	if err != nil {
		log.Fatal(err)
	}
	return bytes.NewReader(out)
}

func GetPrivateKey(keyID string) io.Reader {
	out, err := exec.Command("/usr/bin/gpg", "--export-secret-keys", "--armor", keyID+"!").Output()
	// out, err := exec.Command("cat", "./tests/test.privkey").Output()
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println(string(out))
	return bytes.NewReader(out)
}
