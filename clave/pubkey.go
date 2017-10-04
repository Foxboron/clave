package clave

import (
	"crypto"
	"errors"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

// TODO; Rewrite
func decodePublicKey(pgpkey io.Reader) *packet.PublicKey {

	// open ascii armored public key
	// in, err := os.Open(filename)
	// kingpin.FatalIfError(err, "Error opening public key: %s", err)
	// defer in.Close()

	block, err := armor.Decode(pgpkey)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.PublicKeyType {
		kingpin.FatalIfError(errors.New("Invalid private key file"), "Error decoding private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid public key"), "Error parsing public key")
	}
	return key
}

func createSignature(pgpkey io.Reader) (*packet.Config, *packet.Signature) {
	p := decodePublicKey(pgpkey)
	bitLength, _ := p.BitLength()

	//p := decodePrivateKey("./test.privkey")
	config := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: int(bitLength),
	}

	currTime := config.Now()
	sig := new(packet.Signature)
	sig.SigType = packet.SigTypeBinary
	sig.PubKeyAlgo = p.PubKeyAlgo
	sig.Hash = crypto.SHA256
	sig.CreationTime = currTime
	sig.IssuerKeyId = &p.KeyId

	return config, sig
}
