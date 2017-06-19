rm ./createHash/createHash && rm ./createSignature/createSignature
$(cd ./createHash && go build)
$(cd ./createSignature && go build)
./createHash/createHash test.pubkey test | createSignature/createSignature test.privkey
gpg --verify test.sig test
