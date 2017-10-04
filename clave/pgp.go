package clave

import (
	"io"
	"log"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"mig.ninja/mig/pgp/pinentry"
)

// Use pinentry
func getPinentry() string {
	l := pinentry.Request{Prompt: "Privatekey passphrase"}
	pass, err := l.GetPIN()
	if err != nil {
		log.Fatal(err)
	}
	return pass
}

// Lets decrypt the private key
func decrypt(key *packet.PrivateKey) *packet.PrivateKey {
	passwd := getPinentry()
	err := key.Decrypt([]byte(passwd))
	if err != nil {
		log.Fatal(err)
	}
	return key
}

// TODO: Impelement decryption for armored keys
func getArmoredPrivKey(keyringFileBuffer io.Reader) *packet.PrivateKey {
	block, err := armor.Decode(keyringFileBuffer)
	if err != nil {
		log.Fatal(err)
	}
	if block.Type != openpgp.PrivateKeyType {
		log.Fatal("Didn't find private key inn the armor")
	}
	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		log.Fatal(err)
	}

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		log.Fatal("Unknown error")
	}
	if key.Encrypted {
		return decrypt(key)
	}
	return key
}

// Not really used
func getKeyRingPrivKey(entityList openpgp.EntityList) *packet.PrivateKey {
	// We currently assume this file contains only one privatekey
	// and that its the correct one
	for _, entity := range entityList {
		if entity.PrivateKey.PrivateKey == false {
			continue
		}
		if entity.PrivateKey.Encrypted {
			return decrypt(entity.PrivateKey)
		} else {
			return entity.PrivateKey
		}
	}
	return nil
}

// Search a Keyring for the first privatekey we find
func getPrivateKey(pgpkey io.Reader) *packet.PrivateKey {
	var privateKey *packet.PrivateKey
	privateKey = getArmoredPrivKey(pgpkey)
	return privateKey
}
