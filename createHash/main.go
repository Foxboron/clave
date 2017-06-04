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

func createSignRequest(config *packet.Config, signer *newSignature, h hash.Hash, name string) Sign {
	unixTime, hashDigest := signer.Sign(h, nil, config)
	return Sign{
		Name:     name,
		UnixTime: unixTime,
		Digest:   hex.EncodeToString(hashDigest),
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
