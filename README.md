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
λ → cd createHash && go build && cd -                    
λ → cd createSignature && go build && cd -
```


### Example:

```
# Create signature requests - done remotely
λ → ./createHash/createHash test.pubkey test > test.req
λ → cat test.req
[{"Name":"test","UnixTime":1496578872,"Digest":"971d7fd9645cc30a753bd44b855effb9921e3d1e484904902699f65934f9557b"}]%                                                                                                                     

# Create signatures - done locally
λ → cat test.req | createSignature/createSignature test.privkey

# Verify signature
λ → gpg --verify test.sig test
gpg: Signature made Sun 04 Jun 2017 02:21:12 PM CEST
gpg:                using RSA key 9010FC5907F00B27
gpg: Good signature from "Test Testensen <test@test.no>" [ultimate]
```

