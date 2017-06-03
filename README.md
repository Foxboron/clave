remote-sign
===========
WIP


The goal of this project is to enable remote signing without exposing your private key. it accomplishes this
by creating the hash PGP uses for signing, along with the timestamp. This is then used inn the second part to 
actually create a valid PGP signature.

It utilizes code from:
* https://gist.github.com/eliquious/9e96017f47d9bd43cdf9
* https://github.com/golang/crypto/blob/master/openpgp/packet/signature.go

There is a lot of copypasta involved as i had to work around Golangs export restrictions

### Build
```
λ fox@hackbook remote-sign» cd createHash && go build hash.go && cd -
λ fox@hackbook remote-sign» cd createSignature && go build main.go && cd -

```


### Example:

```
# Create signing hashes - Done remotly
λ fox@hackbook remote-sign» cat test | ./createHash/hash ./test.pubkey
1496527103
6875de26bb4a38ad69d040358f29ca3af1abcb5968fbaf461ecc4d5e5cb1d0b8

# Sign hashes - Done locally
λ fox@hackbook remote-sign» ./createSignature/main --public=test.pubkey --private=test.privkey --timestamp=1496527103
--hash=6875de26bb4a38ad69d040358f29ca3af1abcb5968fbaf461ecc4d5e5cb1d0b8 > test.sig

# Verify
λ fox@hackbook remote-sign » gpg --verify test.sig test
gpg: Signature made Sat 03 Jun 2017 11:58:23 PM CEST
gpg:                using RSA key 9010FC5907F00B27
gpg: Good signature from "Test Testensen <test@test.no>" [ultimate]
```

