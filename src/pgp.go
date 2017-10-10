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

// TODO: This section could probably benefit from code reuse

// Gets an armored public key
func getArmoredPublicKey(pgpkey io.Reader) *packet.PublicKey {

	block, err := armor.Decode(pgpkey)
	if err != nil {
		log.Fatal("Error decoding public key armor")
	}

	if block.Type != openpgp.PublicKeyType {
		log.Fatal("Could not find public key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		log.Fatal(err)
	}

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		log.Fatal("Invalid public key")
	}
	return key
}

func getPublicKey(pgpkey io.Reader) *packet.PublicKey {
	var publickey *packet.PublicKey
	// TODO: Add support for non-armored keys
	publickey = getArmoredPublicKey(pgpkey)
	return publickey
}

// Get an armored private key
func getArmoredPrivKey(pgpkey io.Reader) *packet.PrivateKey {
	block, err := armor.Decode(pgpkey)
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

func getPrivateKey(pgpkey io.Reader) *packet.PrivateKey {
	var privateKey *packet.PrivateKey
	// TODO: Add support for non-armored keys
	privateKey = getArmoredPrivKey(pgpkey)
	return privateKey
}
