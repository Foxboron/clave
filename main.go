package main

import (
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"mig.ninja/mig/pgp/pinentry"
)

func getPinentry() string {
	l := pinentry.Request{Prompt: "Privatekey passphrase"}
	pass, err := l.GetPIN()
	if err != nil {
		log.Fatal(err)
	}
	return pass
}

func decrypt(key *packet.PrivateKey) *packet.PrivateKey {
	passwd := getPinentry()
	err := key.Decrypt([]byte(passwd))
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func getPrivateKey(file string) *packet.PrivateKey {
	keyringFileBuffer, _ := os.Open(file)
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		log.Fatal(err)
	}

	var privateKey *packet.PrivateKey

	for _, entity := range entityList {
		if entity.PrivateKey.PrivateKey == false {
			continue
		}
		if entity.PrivateKey.Encrypted {
			privateKey = decrypt(entity.PrivateKey)
			break
		} else {
			privateKey = entity.PrivateKey
			break
		}
	}
	return privateKey
}

func main() {
	if len(os.Args) < 1 {
		log.Fatal("Need key file")
	}
	// Read in public key
}
