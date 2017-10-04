package clave

import (
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

type SignRequest struct {
	Name     string
	UnixTime int64
	Digest   string
}

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

func createSignRequest(config *packet.Config, signer *packet.Signature, h hash.Hash, name string) SignRequest {
	go _Sign(config, signer, h, name)
	select {
	case s := <-sign:
		return s
	}
}

func CreateSignatureRequest(pgpkey io.Reader, file []string) {
	var replies SignRequests

	config, signer := createSignature(pgpkey)
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
