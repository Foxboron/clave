//
package main

import (
	"encoding/json"
	"log"
	"os"
	"time"

	_ "crypto/sha256"

	_ "golang.org/x/crypto/ripemd160"

	"golang.org/x/crypto/openpgp/packet"
)

type Sign struct {
	Name     string
	UnixTime int64
	Digest   string
}

type Signs []Sign

func signFile(keyFile string, request Sign) {
	privKey := getPrivateKey(keyFile)

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

	// save inn file
	f, err := os.Create("./" + request.Name + ".sig")
	if err != nil {
		log.Fatal(err)
	}
	sig.Serialize(f)

}

func main() {
	if len(os.Args) <= 1 {
		log.Fatal("Need path for private key")
	}
	var signs Signs
	decoder := json.NewDecoder(os.Stdin)
	decoder.UseNumber()
	err := decoder.Decode(&signs)
	if err != nil {
		log.Fatal(err)
	}
	for _, s := range signs {
		signFile(os.Args[1], s)
	}
}
