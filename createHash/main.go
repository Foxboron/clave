package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/openpgp/packet"
)

type Sign struct {
	Name     string
	UnixTime int64
	Digest   string
}

type Reply []Sign

func fileToHash(name string) hash.Hash {
	file, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.New()
	io.Copy(h, file)
	return h
}

var sign = make(chan Sign)

// We rely on Sign not working to get the hash.
// Ugly hack, but we can drop the library copy
func _Sign(config *packet.Config, signer *packet.Signature, h hash.Hash, name string) {
	defer func() {
		if r := recover(); r != nil {
			sign <- Sign{
				Name:     name,
				UnixTime: signer.CreationTime.Unix(),
				Digest:   hex.EncodeToString(h.Sum(nil)),
			}
		}
	}()
	signer.Sign(h, nil, config)
}

func createSignRequest(config *packet.Config, signer *packet.Signature, h hash.Hash, name string) Sign {
	go _Sign(config, signer, h, name)
	select {
	case s := <-sign:
		return s
	}
}

func main() {
	if len(os.Args) <= 2 {
		log.Fatal("Needs path for public key and files to create sign for")
	}

	var replies Reply

	config, signer := createSignature(os.Args[1])
	var h hash.Hash

	for _, file := range os.Args[2:] {
		h = fileToHash(file)
		replies = append(replies, createSignRequest(config, signer, h, file))
	}

	b, err := json.Marshal(replies)
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(b)
}
