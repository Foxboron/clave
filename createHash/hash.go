package main

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

type signatureSubpacketType uint8
type SignatureType uint8

const (
	creationTimeSubpacket        signatureSubpacketType = 2
	signatureExpirationSubpacket signatureSubpacketType = 3
	keyExpirationSubpacket       signatureSubpacketType = 9
	prefSymmetricAlgosSubpacket  signatureSubpacketType = 11
	issuerSubpacket              signatureSubpacketType = 16
	prefHashAlgosSubpacket       signatureSubpacketType = 21
	prefCompressionSubpacket     signatureSubpacketType = 22
	primaryUserIdSubpacket       signatureSubpacketType = 25
	keyFlagsSubpacket            signatureSubpacketType = 27
	reasonForRevocationSubpacket signatureSubpacketType = 29
	featuresSubpacket            signatureSubpacketType = 30
	embeddedSignatureSubpacket   signatureSubpacketType = 32
)
const (
	// See RFC 4880, section 5.2.3.21 for details.
	KeyFlagCertify = 1 << iota
	KeyFlagSign
	KeyFlagEncryptCommunications
	KeyFlagEncryptStorage
)

type outputSubpacket struct {
	hashed        bool // true if this subpacket is in the hashed area.
	subpacketType signatureSubpacketType
	isCritical    bool
	contents      []byte
}

type newSignature struct {
	SigType    packet.SignatureType
	PubKeyAlgo packet.PublicKeyAlgorithm
	Hash       crypto.Hash

	// HashSuffix is extra data that is hashed in after the signed data.
	HashSuffix []byte
	// HashTag contains the first two bytes of the hash for fast rejection
	// of bad signed data.
	HashTag      [2]byte
	CreationTime time.Time

	// rawSubpackets contains the unparsed subpackets, in order.
	rawSubpackets []outputSubpacket

	// The following are optional so are nil when not included in the
	// signature.

	SigLifetimeSecs, KeyLifetimeSecs                        *uint32
	PreferredSymmetric, PreferredHash, PreferredCompression []uint8
	IssuerKeyId                                             *uint64
	IsPrimaryId                                             *bool

	// FlagsValid is set if any flags were given. See RFC 4880, section
	// 5.2.3.21 for details.
	FlagsValid                                                           bool
	FlagCertify, FlagSign, FlagEncryptCommunications, FlagEncryptStorage bool

	// RevocationReason is set if this signature has been revoked.
	// See RFC 4880, section 5.2.3.23 for details.
	RevocationReason     *uint8
	RevocationReasonText string

	// MDC is set if this signature has a feature packet that indicates
	// support for MDC subpackets.
	MDC bool

	outSubpackets []outputSubpacket
}

func (sig *newSignature) buildSubpackets() (subpackets []outputSubpacket) {
	creationTime := make([]byte, 4)
	binary.BigEndian.PutUint32(creationTime, uint32(sig.CreationTime.Unix()))
	subpackets = append(subpackets, outputSubpacket{true, creationTimeSubpacket, false, creationTime})

	if sig.IssuerKeyId != nil {
		keyId := make([]byte, 8)
		binary.BigEndian.PutUint64(keyId, *sig.IssuerKeyId)
		subpackets = append(subpackets, outputSubpacket{true, issuerSubpacket, false, keyId})
	}

	if sig.SigLifetimeSecs != nil && *sig.SigLifetimeSecs != 0 {
		sigLifetime := make([]byte, 4)
		binary.BigEndian.PutUint32(sigLifetime, *sig.SigLifetimeSecs)
		subpackets = append(subpackets, outputSubpacket{true, signatureExpirationSubpacket, true, sigLifetime})
	}

	// Key flags may only appear in self-signatures or certification signatures.

	if sig.FlagsValid {
		var flags byte
		if sig.FlagCertify {
			flags |= KeyFlagCertify
		}
		if sig.FlagSign {
			flags |= KeyFlagSign
		}
		if sig.FlagEncryptCommunications {
			flags |= KeyFlagEncryptCommunications
		}
		if sig.FlagEncryptStorage {
			flags |= KeyFlagEncryptStorage
		}
		subpackets = append(subpackets, outputSubpacket{true, keyFlagsSubpacket, false, []byte{flags}})
	}

	// The following subpackets may only appear in self-signatures

	if sig.KeyLifetimeSecs != nil && *sig.KeyLifetimeSecs != 0 {
		keyLifetime := make([]byte, 4)
		binary.BigEndian.PutUint32(keyLifetime, *sig.KeyLifetimeSecs)
		subpackets = append(subpackets, outputSubpacket{true, keyExpirationSubpacket, true, keyLifetime})
	}

	if sig.IsPrimaryId != nil && *sig.IsPrimaryId {
		subpackets = append(subpackets, outputSubpacket{true, primaryUserIdSubpacket, false, []byte{1}})
	}

	if len(sig.PreferredSymmetric) > 0 {
		subpackets = append(subpackets, outputSubpacket{true, prefSymmetricAlgosSubpacket, false, sig.PreferredSymmetric})
	}

	if len(sig.PreferredHash) > 0 {
		subpackets = append(subpackets, outputSubpacket{true, prefHashAlgosSubpacket, false, sig.PreferredHash})
	}

	if len(sig.PreferredCompression) > 0 {
		subpackets = append(subpackets, outputSubpacket{true, prefCompressionSubpacket, false, sig.PreferredCompression})
	}

	return
}

// subpacketLengthLength returns the length, in bytes, of an encoded length value.
func subpacketLengthLength(length int) int {
	if length < 192 {
		return 1
	}
	if length < 16320 {
		return 2
	}
	return 5
}

// subpacketsLength returns the serialized length, in bytes, of the given
// subpackets.
func subpacketsLength(subpackets []outputSubpacket, hashed bool) (length int) {
	for _, subpacket := range subpackets {
		if subpacket.hashed == hashed {
			length += subpacketLengthLength(len(subpacket.contents) + 1)
			length += 1 // type byte
			length += len(subpacket.contents)
		}
	}
	return
}

// serializeSubpacketLength marshals the given length into to.
func serializeSubpacketLength(to []byte, length int) int {
	// RFC 4880, Section 4.2.2.
	if length < 192 {
		to[0] = byte(length)
		return 1
	}
	if length < 16320 {
		length -= 192
		to[0] = byte((length >> 8) + 192)
		to[1] = byte(length)
		return 2
	}
	to[0] = 255
	to[1] = byte(length >> 24)
	to[2] = byte(length >> 16)
	to[3] = byte(length >> 8)
	to[4] = byte(length)
	return 5
}

// serializeSubpackets marshals the given subpackets into to.
func serializeSubpackets(to []byte, subpackets []outputSubpacket, hashed bool) {
	for _, subpacket := range subpackets {
		if subpacket.hashed == hashed {
			n := serializeSubpacketLength(to, len(subpacket.contents)+1)
			to[n] = byte(subpacket.subpacketType)
			to = to[1+n:]
			n = copy(to, subpacket.contents)
			to = to[n:]
		}
	}
	return
}

// buildHashSuffix constructs the HashSuffix member of sig in preparation for signing.
func (sig *newSignature) buildHashSuffix() (err error) {
	hashedSubpacketsLen := subpacketsLength(sig.outSubpackets, true)

	var ok bool
	l := 6 + hashedSubpacketsLen
	sig.HashSuffix = make([]byte, l+6)
	sig.HashSuffix[0] = 4
	sig.HashSuffix[1] = uint8(sig.SigType)
	sig.HashSuffix[2] = uint8(sig.PubKeyAlgo)
	sig.HashSuffix[3], ok = s2k.HashToHashId(sig.Hash)
	if !ok {
		sig.HashSuffix = nil
		log.Fatal("hash cannot be represented in OpenPGP: " + strconv.Itoa(int(sig.Hash)))
		return nil
	}
	sig.HashSuffix[4] = byte(hashedSubpacketsLen >> 8)
	sig.HashSuffix[5] = byte(hashedSubpacketsLen)
	serializeSubpackets(sig.HashSuffix[6:l], sig.outSubpackets, true)
	trailer := sig.HashSuffix[l:]
	trailer[0] = 4
	trailer[1] = 0xff
	trailer[2] = byte(l >> 24)
	trailer[3] = byte(l >> 16)
	trailer[4] = byte(l >> 8)
	trailer[5] = byte(l)
	return
}

func (sig *newSignature) signPrepareHash(h hash.Hash) (digest []byte, err error) {
	err = sig.buildHashSuffix()
	if err != nil {
		return
	}

	h.Write(sig.HashSuffix)
	digest = h.Sum(nil)
	copy(sig.HashTag[:], digest)
	return
}
func (sig *newSignature) Sign(h hash.Hash, priv *packet.PrivateKey, config *packet.Config) (err error) {
	sig.outSubpackets = sig.buildSubpackets()
	digest, err := sig.signPrepareHash(h)
	if err != nil {
		return
	}
	fmt.Println(sig.CreationTime.Unix())
	fmt.Printf("%x\n", digest)
	return
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

func createSignature() (*packet.Config, *newSignature) {
	p := decodePublicKey("./test.pubkey")
	//p := decodePrivateKey("./test.privkey")
	config := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: 2048,
	}
	currTime := config.Now()
	sig := new(newSignature)
	sig.SigType = packet.SigTypeBinary
	sig.PubKeyAlgo = p.PubKeyAlgo
	sig.Hash = config.Hash()
	sig.CreationTime = currTime
	sig.IssuerKeyId = &p.KeyId

	return config, sig
}

func main() {
	config, signer := createSignature()
	h := sha256.New()
	io.Copy(h, os.Stdin)
	err := signer.Sign(h, nil, config)
	if err != nil {
		return
	}
}
