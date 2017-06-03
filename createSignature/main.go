//
package main

import (
	"encoding/hex"
	"errors"
	"hash"
	"log"
	"os"
	"time"

	"crypto"
	_ "crypto/sha256"

	_ "golang.org/x/crypto/ripemd160"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	// Goencrypt app
	app        = kingpin.New("goencrypt", "A command line tool for encrypting files")
	bits       = app.Flag("bits", "Bits for keys").Default("2048").Int()
	privateKey = app.Flag("private", "Private key").String()
	publicKey  = app.Flag("public", "Public key").String()

	timestamp  = app.Flag("timestamp", "Unix timestamp").Int64()
	hashDigest = app.Flag("hash", "hash from createHash").String()
)

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	default:
		signFile()
	}
}

func decodePrivateKey(filename string) *packet.PrivateKey {

	// open ascii armored private key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening private key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.PrivateKeyType {
		kingpin.FatalIfError(errors.New("Invalid private key file"), "Error decoding private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid private key"), "Error parsing private key")
	}
	return key
}

func decodePublicKey(filename string) *packet.PublicKey {

	// open ascii armored public key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening public key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
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

// We don't want the internal openpgp to mess with our hash
// Override and return SOMETHING
type newHash struct {
	hash.Hash
	sum string
}

func (s newHash) Write(p []byte) (nn int, err error) {
	return 0, nil
}

func (s newHash) Size() int {
	return 32
}

func (s newHash) Sum(h []byte) []byte {
	decoded, err := hex.DecodeString(s.sum)
	if err != nil {
		log.Fatal(err)
	}
	return decoded
}

func signFile() {

	pubKey := decodePublicKey(*publicKey)
	privKey := decodePrivateKey(*privateKey)

	signer := createEntityFromKeys(pubKey, privKey)

	//err := openpgp.ArmoredDetachSign(os.Stdout, signer, os.Stdin, nil)
	//kingpin.FatalIfError(err, "Error signing input")
	sig := new(packet.Signature)
	sig.SigType = packet.SigTypeBinary
	sig.PubKeyAlgo = signer.PrivateKey.PubKeyAlgo
	config := &packet.Config{}
	sig.Hash = config.Hash()
	sig.IssuerKeyId = &signer.PrivateKey.KeyId

	sig.CreationTime = time.Unix(*timestamp, 0)
	h := newHash{sum: *hashDigest}

	err := sig.Sign(h, signer.PrivateKey, config)
	if err != nil {
		log.Fatal(err)
	}
	sig.Serialize(os.Stdout)

}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: *bits,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false
	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}
