package clave

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"log"
	"os"
	"time"

	"crypto/sha256"

	_ "golang.org/x/crypto/ripemd160"

	"golang.org/x/crypto/openpgp/packet"
)

// Signature requests
// UnixTime is for the timestamp to generate signature
// Digest is the signing hash used by PGP
type SignRequest struct {
	Name     string
	UnixTime int64
	Digest   string
}

// List of signature requests
type SignRequests []SignRequest

func fileToHash(name string) hash.Hash {
	file, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.New()
	io.Copy(h, file)
	return h
}

// Channel so we can recieve the signing request
var sign = make(chan SignRequest)

// We rely on Sign not working to get the hash.
// Ugly hack, but we can drop the library copy
func _Sign(config *packet.Config, signer *packet.Signature, h hash.Hash, name string) {
	defer func() {
		if r := recover(); r != nil {
			sign <- SignRequest{
				Name:     name,
				UnixTime: signer.CreationTime.Unix(),
				Digest:   hex.EncodeToString(h.Sum(nil)),
			}
		}
	}()
	signer.Sign(h, nil, config)
}

/* Since the Sign function will crash it needs to
be dispatched into its own thread so we can recover
*/
func createSignRequest(config *packet.Config, signer *packet.Signature, h hash.Hash, name string) SignRequest {
	go _Sign(config, signer, h, name)
	select {
	case s := <-sign:
		return s
	}
}

// Creates the signature request for multiple files
func CreateSignatureRequest(pgpkey io.Reader, file []string) {
	var replies SignRequests

	config, signer := createInitialSignatureConfig(pgpkey)
	var h hash.Hash

	for _, file := range file {
		h = fileToHash(file)
		replies = append(replies, createSignRequest(config, signer, h, file))
	}

	b, err := json.Marshal(replies)
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(b)
}

// Takes a signature request and returns a real signature
func CreateSignature(pgpkey io.Reader, request SignRequest) {
	privKey := getPrivateKey(pgpkey)
	sig := new(packet.Signature)
	sig.SigType = packet.SigTypeBinary
	sig.PubKeyAlgo = privKey.PubKeyAlgo
	config := &packet.Config{}
	sig.Hash = config.Hash()
	sig.IssuerKeyId = &privKey.KeyId

	sig.CreationTime = time.Unix(request.UnixTime, 0)
	h := newHash{sum: request.Digest}

	err := sig.Sign(h, privKey, config)
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Create("./" + request.Name + ".sig")
	if err != nil {
		log.Fatal(err)
	}
	sig.Serialize(f)
}

// Generates the initial signature request
func createInitialSignatureConfig(pgpkey io.Reader) (*packet.Config, *packet.Signature) {
	p := getPublicKey(pgpkey)
	bitLength, _ := p.BitLength()

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
