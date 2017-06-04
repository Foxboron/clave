package main

import (
	"encoding/hex"
	"hash"
	"log"
)

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
